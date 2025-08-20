#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import argparse
import sys
import math
import time
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecretMatch:
    file_path: str
    line_number: int
    line_content: str
    secret_type: str
    matched_text: str
    confidence: str


class ProgressBar:
    def __init__(self, width: int = 50):
        self.width = width
        self.files_scanned = 0
        self.folders_scanned = 0
        self.secrets_found = 0
        self.start_time = time.time()
        self.last_update = 0
        
    def update(self, files: int = 0, folders: int = 0, secrets: int = 0, force: bool = False):
        self.files_scanned += files
        self.folders_scanned += folders
        self.secrets_found += secrets
        
        current_time = time.time()
        # Update at most 20 times per second to avoid flickering, unless forced
        if not force and current_time - self.last_update < 0.05:
            return
        self.last_update = current_time
        
        # Create animated progress bar
        elapsed = current_time - self.start_time
        animation_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        spinner = animation_chars[int(elapsed * 10) % len(animation_chars)]
        
        # Progress bar with file count
        progress_text = f"{spinner} Scanning... Files: {self.files_scanned:,} | Folders: {self.folders_scanned:,}"
        if self.secrets_found > 0:
            progress_text += f" | Secrets: {self.secrets_found:,} ⚠️"
        
        # Clear line and print progress
        print(f"\r{progress_text}", end="", flush=True)
    
    def finish(self, total_matches: int):
        elapsed = time.time() - self.start_time
        print(f"\r✅ Scan complete! Files: {self.files_scanned:,} | Folders: {self.folders_scanned:,} | Time: {elapsed:.1f}s")
        if total_matches > 0:
            print(f"🚨 Found {total_matches:,} potential secret(s)")
        print()


class SecretScanner:
    def __init__(self):
        self.secret_patterns = {
            # Only very specific, high-confidence patterns
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36}',
            'GitHub Personal Access Token': r'ghp_[A-Za-z0-9]{36}',
            'Stripe Live Key': r'sk_live_[A-Za-z0-9]{24}',
            'Stripe Test Key': r'sk_test_[A-Za-z0-9]{24}',
            'Stripe Publishable Key': r'pk_(?:live|test)_[A-Za-z0-9]{24}',
            'Google API Key': r'AIza[0-9A-Za-z_-]{35}',
            'Slack Token': r'xox[baprs]-[A-Za-z0-9-]+',
            'Mailgun API Key': r'key-[A-Za-z0-9]{32}',
            'SendGrid API Key': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            'JWT Token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'SSH Private Key': r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
            # AI Provider API Keys (Major Addition!)
            'OpenAI API Key': r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',
            'OpenAI API Key (New Format)': r'sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',
            'Anthropic API Key': r'sk-ant-api03-[A-Za-z0-9_-]{95}',
            'Google API Key (Gemini)': r'AIza[0-9A-Za-z_-]{35}',
            'Cohere API Key': r'[A-Za-z0-9]{40}-[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}',
            'Hugging Face Token': r'hf_[A-Za-z0-9]{34}',
            'Replicate API Token': r'r8_[A-Za-z0-9]{32}',
            # Much more restrictive patterns for common false positives
            'Hardcoded Password': r'["\'][a-zA-Z0-9!@#$%^&*()_+=\[\]{}|;:,.<>?-]{12,}["\']',  # Only long, complex passwords
            'Database URL with Credentials': r'[a-zA-Z]+://[^\s:@]+:[^\s:@]{8,}@[^\s@]+',  # Must have 8+ char password
        }
        
        self.file_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
            '.yaml', '.yml', '.json', '.xml', '.toml', '.ini', '.cfg',
            '.env', '.properties', '.conf', '.config', '.txt', '.md',
            '.dockerfile', '.makefile', '.gradle', '.maven'
        }
        
        self.ignore_patterns = {
            r'#.*',  # Comments
            r'//.*',  # Comments
            r'/\*.*?\*/',  # Block comments
            r'<!--.*?-->',  # HTML comments
        }

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        
        probabilities = {}
        for char in text:
            probabilities[char] = probabilities.get(char, 0) + 1
        
        entropy = 0.0
        text_len = len(text)
        for count in probabilities.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy

    def is_high_entropy_string(self, text: str, min_length: int = 32, entropy_threshold: float = 5.0) -> bool:
        if len(text) < min_length:
            return False
        
        # Skip common false positives
        text_lower = text.lower()
        false_positives = [
            'lorem', 'ipsum', 'example', 'test', 'dummy', 'placeholder',
            'abcdef', '123456', 'qwerty', 'password', 'xxxxxxxx', 'sample',
            'demo', 'mock', 'fake', 'template', 'default', 'null', 'undefined',
            'binary', 'encoded', 'base64', 'hash', 'checksum', 'uuid', 'guid'
        ]
        
        if any(fp in text_lower for fp in false_positives):
            return False
        
        # Skip if it looks like a hash (hex only)
        if len(text) >= 32 and all(c in '0123456789abcdefABCDEF' for c in text):
            return False
            
        # Skip if it's mostly repeated characters
        unique_chars = len(set(text))
        if unique_chars < len(text) * 0.3:  # Less than 30% unique chars
            return False
        
        entropy = self.calculate_entropy(text)
        return entropy > entropy_threshold

    def extract_strings_from_line(self, line: str) -> List[str]:
        string_patterns = [
            r'"([^"\\]|\\.)*"',  # Double quoted strings
            r"'([^'\\]|\\.)*'",  # Single quoted strings
            r'`([^`\\]|\\.)*`',  # Backtick strings
        ]
        
        strings = []
        for pattern in string_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                # Remove the quotes
                string_content = match.group()[1:-1]
                if string_content:
                    strings.append(string_content)
        
        return strings

    def is_likely_comment(self, line: str) -> bool:
        stripped = line.strip()
        return (stripped.startswith('#') or 
                stripped.startswith('//') or 
                stripped.startswith('/*') or 
                stripped.startswith('*') or
                stripped.startswith('<!--'))
                
    def should_skip_file_for_secrets(self, file_path: str) -> bool:
        """Check if this file should be skipped entirely for secret detection"""
        file_path_lower = file_path.lower()
        
        # Skip translation/localization files (major source of false positives)
        if any(path_part in file_path_lower for path_part in 
              ['/locales/', '/translations/', '/i18n/', 'translation.json', 'locale.json']):
            return True
        
        # Skip test files (but only obvious ones)
        if any(test_indicator in file_path_lower for test_indicator in 
              ['.test.', '.spec.', '__tests__/', '/tests/', '/test/', '.mock.']):
            return True
        
        # Skip GitHub Actions and CI files
        if '.github/workflows/' in file_path_lower and file_path_lower.endswith(('.yml', '.yaml')):
            return True
            
        # Skip package.json and common config files
        if file_path_lower.endswith(('package.json', 'package-lock.json')):
            return True
            
        return False

    def is_likely_real_secret(self, matched_text: str, secret_type: str, line: str, file_path: str) -> bool:
        """GENIUS context-aware filtering to eliminate false positives"""
        line_lower = line.lower()
        matched_lower = matched_text.lower()
        
        # Universal exclusions - these are NEVER secrets
        universal_false_positives = [
            # Import/require statements  
            'import', 'require', 'from ', 'export',
            # Translation keys and UI text (major source of false positives)
            '":', "':", 'localize(', 'translate(',
            # Comments and documentation
            '//', '/*', '<!--', '#',
            # Test data indicators
            'mock', 'fake', 'example', 'dummy',
            # Field names and form inputs
            'field', 'input', 'placeholder', 'label',
            # Configuration keys (not values)
            '_key":', '_password":', '_secret":',
            # UI/HTML attributes
            'type=', 'name=', 'id=', 'class=',
        ]
        
        if any(indicator in line_lower for indicator in universal_false_positives):
            return False
        
        # Specific pattern filtering
        if secret_type == "Hardcoded Password":
            # Only flag if it looks like an actual password assignment
            if not any(assignment in line_lower for assignment in 
                      ['password =', 'password:', 'pwd =', 'pass =']):
                return False
            # Skip simple test passwords
            if any(simple in matched_lower for simple in 
                  ['password', '123456', 'test', 'admin', 'user']):
                return False
            # Must have complexity (mixed case, numbers, symbols)
            has_upper = any(c.isupper() for c in matched_text)
            has_lower = any(c.islower() for c in matched_text)
            has_digit = any(c.isdigit() for c in matched_text)
            has_symbol = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in matched_text)
            if sum([has_upper, has_lower, has_digit, has_symbol]) < 2:
                return False
        
        elif secret_type == "Database URL with Credentials":
            # Skip example/test URLs
            if any(test_indicator in line_lower for test_indicator in 
                  ['example.com', 'localhost', 'test', 'mock']):
                return False
        
        elif secret_type in ["JWT Token"]:
            # Skip if it's clearly a variable or function call
            if any(code_indicator in line_lower for code_indicator in 
                  ['.decode', '.verify', '.sign', 'jwt.', 'token.']):
                return False
        
        # Check for environment variable patterns (major source of false positives)
        env_patterns = [
            'process.env', 'getenv', 'environment', '${', 'env.',
            'config.', 'settings.', 'options.', 'this.'
        ]
        if any(env_pattern in line_lower for env_pattern in env_patterns):
            return False
        
        # Skip if matched text contains obvious variable references
        if any(var_indicator in matched_text for var_indicator in ['${', '{{', '${', '%']):
            return False
        
        return True

    def scan_line(self, line: str, line_number: int, file_path: str) -> List[SecretMatch]:
        matches = []
        
        # Skip entire files that are likely to have false positives
        if self.should_skip_file_for_secrets(file_path):
            return matches
        
        # Skip comments (but not entirely, as secrets might be in commented code)
        if self.is_likely_comment(line):
            return matches
        
        # Check regex patterns
        for secret_type, pattern in self.secret_patterns.items():
            regex_matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in regex_matches:
                matched_text = match.group(1) if match.groups() else match.group()
                
                # Apply intelligent context filtering
                if not self.is_likely_real_secret(matched_text, secret_type, line, file_path):
                    continue
                
                matches.append(SecretMatch(
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line.strip(),
                    secret_type=secret_type,
                    matched_text=matched_text,
                    confidence="High"
                ))
        
        # Check for high-entropy strings (unique feature!) - but be more conservative
        strings = self.extract_strings_from_line(line)
        for string in strings:
            if self.is_high_entropy_string(string):
                matches.append(SecretMatch(
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line.strip(),
                    secret_type="High Entropy String",
                    matched_text=string,
                    confidence="Medium"
                ))
        
        return matches

    def should_scan_file(self, file_path: Path) -> bool:
        # Check file extension first (fastest check)
        if file_path.suffix.lower() not in self.file_extensions:
            return False
        
        # Skip binary files and common ignore patterns
        ignore_dirs = {'.git', '.svn', '.hg', '__pycache__', 'node_modules', 
                      '.pytest_cache', '.mypy_cache', 'venv', 'env', '.venv',
                      '.tox', 'dist', 'build', '.egg-info', 'coverage',
                      '.nyc_output', '.sass-cache', '.parcel-cache', '.cache'}
        
        # Skip minified files and compiled assets (major source of false positives)
        name = file_path.name.lower()
        if ('.min.' in name or name.endswith('.min.js') or name.endswith('.min.css') or
            name.endswith('.bundle.js') or name.endswith('.chunk.js') or
            name.endswith('.compiled.js') or name.endswith('.generated.js') or
            'vendor' in name or 'bundle' in name):
            return False
        
        # Check if any part of the path contains ignored directories
        path_parts = set(file_path.parts)
        if path_parts.intersection(ignore_dirs):
            return False
            
        # Skip very large files (>1MB) to avoid hanging
        try:
            if file_path.stat().st_size > 1024 * 1024:
                return False
        except (OSError, PermissionError):
            return False
        
        return True

    def should_scan_directory(self, dir_path: Path) -> bool:
        # Skip common ignore directories entirely
        ignore_dirs = {'.git', '.svn', '.hg', '__pycache__', 'node_modules',
                      '.pytest_cache', '.mypy_cache', 'venv', 'env', '.venv',
                      '.tox', 'dist', 'build', '.egg-info', 'coverage',
                      '.nyc_output', '.sass-cache', '.parcel-cache', '.cache',
                      'Pods', 'DerivedData', '.Trash', 'Library'}
        
        return dir_path.name not in ignore_dirs

    def scan_file(self, file_path: str) -> List[SecretMatch]:
        matches = []
        path = Path(file_path)
        
        if not self.should_scan_file(path):
            return matches
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_number, line in enumerate(file, 1):
                    line_matches = self.scan_line(line, line_number, file_path)
                    matches.extend(line_matches)
        except (PermissionError, UnicodeDecodeError, FileNotFoundError):
            pass  # Skip files we can't read
        
        return matches

    def scan_directory(self, directory_path: str, progress_bar: ProgressBar = None) -> List[SecretMatch]:
        matches = []
        path = Path(directory_path)
        
        if not path.exists():
            print(f"Error: Path '{directory_path}' does not exist")
            return matches
        
        if path.is_file():
            return self.scan_file(directory_path)
        
        folders_seen = set()
        file_count = 0
        
        # Use iterdir() with recursion to have better control
        def scan_recursive(current_path: Path):
            nonlocal file_count, folders_seen
            
            try:
                # Check if we should skip this directory
                if not self.should_scan_directory(current_path):
                    return
                
                # Add this folder to seen folders
                folder_key = str(current_path)
                if folder_key not in folders_seen:
                    folders_seen.add(folder_key)
                    if progress_bar:
                        progress_bar.update(folders=1)
                
                # Process items in this directory
                items = list(current_path.iterdir())
                for item in items:
                    file_count += 1
                    
                    # Update progress every 10 files to stay responsive
                    if file_count % 10 == 0 and progress_bar:
                        progress_bar.update(force=True)
                    
                    if item.is_dir():
                        # Recursively scan subdirectory
                        scan_recursive(item)
                    elif item.is_file():
                        # Check if we should scan this file
                        if self.should_scan_file(item):
                            file_matches = self.scan_file(str(item))
                            matches.extend(file_matches)
                            
                            if progress_bar:
                                progress_bar.update(files=1, secrets=len(file_matches))
                        else:
                            # Still count skipped files for progress
                            if progress_bar:
                                progress_bar.update(files=1)
                                
            except (PermissionError, OSError):
                # Skip directories we can't access
                pass
        
        scan_recursive(path)
        return matches


def filter_matches(matches: List[SecretMatch], filter_term: str = None, confidence_level: str = 'all') -> List[SecretMatch]:
    """Filter matches by secret type and confidence level"""
    filtered = matches
    
    # Filter by confidence level
    if confidence_level == 'high':
        filtered = [m for m in filtered if m.confidence == 'High']
    elif confidence_level == 'medium':
        filtered = [m for m in filtered if m.confidence == 'Medium']
    
    # Filter by secret type (case-insensitive partial match)
    if filter_term:
        filter_term_lower = filter_term.lower()
        filtered = [m for m in filtered if filter_term_lower in m.secret_type.lower()]
    
    return filtered


def format_output(matches: List[SecretMatch], show_content: bool = True) -> str:
    if not matches:
        return "[CLEAN] No potential secrets found!"
    
    output = []
    output.append(f"[ALERT] Found {len(matches)} potential secret(s):\\n")
    
    # Group by file for better readability
    files = {}
    for match in matches:
        if match.file_path not in files:
            files[match.file_path] = []
        files[match.file_path].append(match)
    
    for file_path, file_matches in files.items():
        output.append(f"[FILE] {file_path}")
        for match in file_matches:
            confidence_icon = "[HIGH]" if match.confidence == "High" else "[MED]"
            output.append(f"  {confidence_icon} Line {match.line_number}: {match.secret_type}")
            if show_content:
                output.append(f"     Content: {match.line_content[:100]}...")
                output.append(f"     Match: {match.matched_text}")
            output.append("")
    
    return "\\n".join(output)


def generate_secrets_report(matches: List[SecretMatch], total_files: int, total_folders: int, scan_time: float, filter_info: str = "") -> str:
    """Generate a detailed markdown report of found secrets"""
    from datetime import datetime
    import os
    
    report = []
    report.append("# Secret Scanner Report")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Scan Summary:** {total_files:,} files in {total_folders:,} folders scanned in {scan_time:.1f}s")
    if filter_info:
        report.append(f"**Filter Applied:** {filter_info}")
    report.append(f"**Total Secrets Found:** {len(matches):,}")
    report.append("")
    
    if not matches:
        report.append("## Clean Scan")
        report.append("No potential secrets detected in the scanned files.")
        return "\\n".join(report)
    
    # Group by folder > file > secrets
    folder_groups = {}
    for match in matches:
        folder = os.path.dirname(match.file_path)
        filename = os.path.basename(match.file_path)
        
        if folder not in folder_groups:
            folder_groups[folder] = {}
        if filename not in folder_groups[folder]:
            folder_groups[folder][filename] = []
        folder_groups[folder][filename].append(match)
    
    # Summary stats
    high_confidence = sum(1 for m in matches if m.confidence == "High")
    medium_confidence = sum(1 for m in matches if m.confidence == "Medium")
    
    report.append("## Summary")
    report.append(f"- **High Confidence:** {high_confidence:,} secrets")
    report.append(f"- **Medium Confidence:** {medium_confidence:,} secrets")
    report.append(f"- **Files Affected:** {len(set(m.file_path for m in matches)):,}")
    report.append(f"- **Folders Affected:** {len(folder_groups):,}")
    report.append("")
    
    # Secret type breakdown
    secret_types = {}
    for match in matches:
        secret_types[match.secret_type] = secret_types.get(match.secret_type, 0) + 1
    
    report.append("## Secret Types Found")
    for secret_type, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
        report.append(f"- **{secret_type}:** {count:,}")
    report.append("")
    
    # Detailed findings by folder
    report.append("## Detailed Findings")
    
    for folder_path in sorted(folder_groups.keys()):
        report.append(f"### `{folder_path}`")
        report.append("")
        
        for filename in sorted(folder_groups[folder_path].keys()):
            file_matches = folder_groups[folder_path][filename]
            report.append(f"#### `{filename}` ({len(file_matches)} secrets)")
            report.append("")
            
            for match in sorted(file_matches, key=lambda x: x.line_number):
                confidence_emoji = "HIGH" if match.confidence == "High" else "MED"
                report.append(f"- **Line {match.line_number}:** {match.secret_type} ({confidence_emoji})")
                report.append(f"  - **Match:** `{match.matched_text[:50]}{'...' if len(match.matched_text) > 50 else ''}`")
                report.append(f"  - **Context:** `{match.line_content[:80]}{'...' if len(match.line_content) > 80 else ''}`")
                report.append("")
        report.append("")
    
    report.append("## Next Steps")
    report.append("1. **Review HIGH confidence findings first** - these are most likely real secrets")
    report.append("2. **Remove or replace secrets** with environment variables or secret management")
    report.append("3. **Rotate any exposed secrets** immediately")
    report.append("4. **Add secret scanning to your CI/CD pipeline** to prevent future commits")
    report.append("")
    report.append("---")
    report.append("*Generated by Simple Secret Scanner*")
    
    return "\\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description="Simple Secret Scanner - Detect hardcoded secrets in code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s .                    # Scan current directory
  %(prog)s /path/to/project     # Scan specific directory
  %(prog)s file.py              # Scan single file
  %(prog)s . --no-content       # Scan without showing line content
        """
    )
    
    parser.add_argument('path', 
                       help='File or directory to scan')
    parser.add_argument('--no-content', 
                       action='store_true',
                       help='Hide line content in output')
    parser.add_argument('--quiet', '-q',
                       action='store_true', 
                       help='Only show summary')
    parser.add_argument('--report', '-r',
                       action='store_true',
                       help='Generate secrets.md report file')
    parser.add_argument('--filter',
                       type=str,
                       help='Filter results by secret type (case-insensitive partial match)')
    parser.add_argument('--confidence',
                       choices=['high', 'medium', 'all'],
                       default='all',
                       help='Filter by confidence level (default: all)')
    
    args = parser.parse_args()
    
    scanner = SecretScanner()
    
    if not args.quiet:
        print("Simple Secret Scanner")
        print("=" * 40)
        print(f"Scanning: {args.path}")
        print()
    
    # Check if we're scanning a directory (not a single file)
    scan_path = Path(args.path)
    show_progress = not args.quiet and scan_path.is_dir()
    
    progress_bar = ProgressBar() if show_progress else None
    
    start_time = time.time()
    matches = scanner.scan_directory(args.path, progress_bar)
    scan_time = time.time() - start_time
    
    total_files = progress_bar.files_scanned if progress_bar else 0
    total_folders = progress_bar.folders_scanned if progress_bar else 0
    
    if progress_bar:
        progress_bar.finish(len(matches))
    
    # Apply filters
    original_count = len(matches)
    filtered_matches = filter_matches(matches, args.filter, args.confidence)
    
    # Create filter info string for reporting
    filter_info = []
    if args.filter:
        filter_info.append(f"Secret type contains '{args.filter}'")
    if args.confidence != 'all':
        filter_info.append(f"Confidence level: {args.confidence}")
    filter_description = ", ".join(filter_info) if filter_info else ""
    
    # Show filter results if filters were applied
    if args.filter or args.confidence != 'all':
        if not args.quiet:
            print(f"Filter applied: {filter_description}")
            print(f"Results: {len(filtered_matches):,} of {original_count:,} matches")
            print()
    
    # Generate report if requested
    if args.report:
        # Use filtered matches for report
        report_content = generate_secrets_report(filtered_matches, total_files, total_folders, scan_time, filter_description)
        with open('secrets.md', 'w') as f:
            f.write(report_content)
        print(f"Report saved to secrets.md ({len(filtered_matches):,} secrets found)")
    
    if args.quiet:
        sys.exit(0 if not filtered_matches else 1)
    
    # Use filtered matches for output
    output = format_output(filtered_matches, show_content=not args.no_content)
    print(output)
    
    if filtered_matches:
        print("\\n[WARNING] Security Alert:")
        print("Potential secrets detected! Review these findings carefully.")
        print("Remove any real secrets and use environment variables or")
        print("secure secret management solutions instead.")
        sys.exit(1)


if __name__ == "__main__":
    main()