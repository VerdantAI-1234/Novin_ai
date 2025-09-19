"""
Sanitizer Module

Comprehensive data sanitization and validation for the security reasoner system.
Provides input cleaning, validation, and normalization capabilities to ensure
data integrity and prevent injection attacks.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union, Callable, Pattern
import re
import html
import json
import ipaddress
import urllib.parse
from datetime import datetime
from email.utils import parseaddr
import hashlib
import base64


@dataclass
class SanitizationRule:
    """Configuration for a sanitization rule"""
    name: str
    pattern: Pattern[str]
    replacement: str = ""
    flags: int = re.IGNORECASE
    description: str = ""
    
    def apply(self, text: str) -> str:
        """Apply the sanitization rule to text"""
        return self.pattern.sub(self.replacement, text)


@dataclass
class ValidationRule:
    """Configuration for a validation rule"""
    name: str
    validator: Callable[[Any], bool]
    error_message: str
    required: bool = True
    description: str = ""
    
    def validate(self, value: Any) -> tuple[bool, str]:
        """Validate a value against this rule"""
        try:
            is_valid = self.validator(value)
            return is_valid, "" if is_valid else self.error_message
        except Exception as e:
            return False, f"Validation error: {str(e)}"


@dataclass
class SanitizationResult:
    """Result of sanitization operation"""
    original_value: Any
    sanitized_value: Any
    rules_applied: List[str]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    is_valid: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "original_value": str(self.original_value),
            "sanitized_value": self.sanitized_value,
            "rules_applied": self.rules_applied,
            "warnings": self.warnings,
            "errors": self.errors,
            "is_valid": self.is_valid
        }


class SecuritySanitizer:
    """
    Comprehensive security-focused data sanitizer.
    
    Provides sanitization, validation, and normalization for various data types
    with particular focus on security event data and preventing injection attacks.
    """
    
    def __init__(self):
        """Initialize security sanitizer with default rules"""
        self.sanitization_rules: Dict[str, SanitizationRule] = {}
        self.validation_rules: Dict[str, ValidationRule] = {}
        self.field_processors: Dict[str, Callable] = {}
        
        # Configuration - set before rules setup
        self.max_string_length = 10000
        self.max_list_length = 1000
        self.max_dict_depth = 10
        self.enable_html_sanitization = True
        self.enable_sql_injection_protection = True
        self.enable_xss_protection = True
        self.strict_mode = False
        
        # Initialize default rules
        self._setup_default_sanitization_rules()
        self._setup_default_validation_rules()
        self._setup_field_processors()
    
    def _setup_default_sanitization_rules(self) -> None:
        """Setup default sanitization rules"""
        
        # XSS protection
        self.sanitization_rules["remove_script_tags"] = SanitizationRule(
            name="remove_script_tags",
            pattern=re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            replacement="",
            description="Remove script tags to prevent XSS"
        )
        
        self.sanitization_rules["remove_on_events"] = SanitizationRule(
            name="remove_on_events",
            pattern=re.compile(r'\bon\w+\s*=\s*["\'][^"\']*["\']', re.IGNORECASE),
            replacement="",
            description="Remove on* event handlers"
        )
        
        # SQL injection protection
        self.sanitization_rules["remove_sql_comments"] = SanitizationRule(
            name="remove_sql_comments",
            pattern=re.compile(r'(--|#|/\*|\*/)', re.IGNORECASE),
            replacement="",
            description="Remove SQL comment indicators"
        )
        
        self.sanitization_rules["escape_sql_quotes"] = SanitizationRule(
            name="escape_sql_quotes",
            pattern=re.compile(r"('|\")", re.IGNORECASE),
            replacement=r"\\\1",
            description="Escape SQL quotes"
        )
        
        # Control characters
        self.sanitization_rules["remove_control_chars"] = SanitizationRule(
            name="remove_control_chars",
            pattern=re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'),
            replacement="",
            description="Remove control characters"
        )
        
        # Path traversal protection
        self.sanitization_rules["remove_path_traversal"] = SanitizationRule(
            name="remove_path_traversal",
            pattern=re.compile(r'\.\./', re.IGNORECASE),
            replacement="",
            description="Remove path traversal sequences"
        )
        
        # Command injection protection
        self.sanitization_rules["remove_command_chars"] = SanitizationRule(
            name="remove_command_chars",
            pattern=re.compile(r'[;&|`$]'),
            replacement="",
            description="Remove command injection characters"
        )
    
    def _setup_default_validation_rules(self) -> None:
        """Setup default validation rules"""
        
        # String length validation
        self.validation_rules["max_length"] = ValidationRule(
            name="max_length",
            validator=lambda x: len(str(x)) <= self.max_string_length,
            error_message=f"String exceeds maximum length of {self.max_string_length}",
            description="Validate string length"
        )
        
        # Email validation
        self.validation_rules["email_format"] = ValidationRule(
            name="email_format",
            validator=self._validate_email,
            error_message="Invalid email format",
            required=False,
            description="Validate email format"
        )
        
        # IP address validation
        self.validation_rules["ip_address"] = ValidationRule(
            name="ip_address",
            validator=self._validate_ip_address,
            error_message="Invalid IP address format",
            required=False,
            description="Validate IP address format"
        )
        
        # URL validation
        self.validation_rules["url_format"] = ValidationRule(
            name="url_format",
            validator=self._validate_url,
            error_message="Invalid URL format",
            required=False,
            description="Validate URL format"
        )
        
        # JSON validation
        self.validation_rules["json_format"] = ValidationRule(
            name="json_format",
            validator=self._validate_json,
            error_message="Invalid JSON format",
            required=False,
            description="Validate JSON format"
        )
        
        # Base64 validation
        self.validation_rules["base64_format"] = ValidationRule(
            name="base64_format",
            validator=self._validate_base64,
            error_message="Invalid Base64 format",
            required=False,
            description="Validate Base64 encoding"
        )
    
    def _setup_field_processors(self) -> None:
        """Setup field-specific processors"""
        
        self.field_processors.update({
            "email": self.sanitize_email,
            "ip_address": self.sanitize_ip_address,
            "url": self.sanitize_url,
            "filename": self.sanitize_filename,
            "user_id": self.sanitize_user_id,
            "event_id": self.sanitize_event_id,
            "timestamp": self.sanitize_timestamp,
            "json_data": self.sanitize_json,
            "description": self.sanitize_text,
            "message": self.sanitize_text,
            "command": self.sanitize_command,
            "file_path": self.sanitize_file_path
        })
    
    def sanitize_data(self, data: Any, field_type: Optional[str] = None) -> SanitizationResult:
        """
        Sanitize arbitrary data based on type and content.
        
        Args:
            data: Data to sanitize
            field_type: Optional field type for specialized processing
            
        Returns:
            SanitizationResult with sanitized data and metadata
        """
        if data is None:
            return SanitizationResult(
                original_value=data,
                sanitized_value=data,
                rules_applied=[],
                is_valid=True
            )
        
        # Use field-specific processor if available
        if field_type and field_type in self.field_processors:
            return self.field_processors[field_type](data)
        
        # Determine processing based on data type
        if isinstance(data, str):
            return self.sanitize_text(data)
        elif isinstance(data, dict):
            return self.sanitize_dict(data)
        elif isinstance(data, list):
            return self.sanitize_list(data)
        elif isinstance(data, (int, float, bool)):
            return self.sanitize_primitive(data)
        else:
            # Convert to string and sanitize
            return self.sanitize_text(str(data))
    
    def sanitize_text(self, text: str) -> SanitizationResult:
        """
        Sanitize text content with comprehensive security measures.
        
        Args:
            text: Text to sanitize
            
        Returns:
            SanitizationResult with sanitized text
        """
        if not isinstance(text, str):
            text = str(text)
        
        original_text = text
        rules_applied = []
        warnings = []
        errors = []
        
        # Length validation
        if len(text) > self.max_string_length:
            text = text[:self.max_string_length]
            warnings.append(f"Text truncated to {self.max_string_length} characters")
            rules_applied.append("length_truncation")
        
        # Apply sanitization rules
        for rule_name, rule in self.sanitization_rules.items():
            if rule.pattern.search(text):
                text = rule.apply(text)
                rules_applied.append(rule_name)
        
        # HTML entity encoding for additional safety
        if self.enable_html_sanitization:
            text = html.escape(text)
            rules_applied.append("html_escape")
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        if text != original_text.strip():
            rules_applied.append("whitespace_normalization")
        
        # Validate result
        is_valid = True
        for validation_name, validation in self.validation_rules.items():
            if validation.required or validation_name == "max_length":
                valid, error_msg = validation.validate(text)
                if not valid:
                    is_valid = False
                    errors.append(error_msg)
        
        return SanitizationResult(
            original_value=original_text,
            sanitized_value=text,
            rules_applied=rules_applied,
            warnings=warnings,
            errors=errors,
            is_valid=is_valid
        )
    
    def sanitize_dict(self, data: Dict[str, Any], depth: int = 0) -> SanitizationResult:
        """
        Sanitize dictionary data recursively.
        
        Args:
            data: Dictionary to sanitize
            depth: Current recursion depth
            
        Returns:
            SanitizationResult with sanitized dictionary
        """
        if depth > self.max_dict_depth:
            return SanitizationResult(
                original_value=data,
                sanitized_value={},
                rules_applied=["max_depth_exceeded"],
                errors=[f"Dictionary depth exceeds maximum of {self.max_dict_depth}"],
                is_valid=False
            )
        
        sanitized_dict = {}
        rules_applied = []
        warnings = []
        errors = []
        
        for key, value in data.items():
            # Sanitize key
            key_result = self.sanitize_text(str(key))
            sanitized_key = key_result.sanitized_value
            
            if not key_result.is_valid:
                errors.extend(key_result.errors)
                continue
            
            # Sanitize value
            value_result = self.sanitize_data(value, field_type=self._detect_field_type(key))
            
            sanitized_dict[sanitized_key] = value_result.sanitized_value
            rules_applied.extend(value_result.rules_applied)
            warnings.extend(value_result.warnings)
            errors.extend(value_result.errors)
        
        return SanitizationResult(
            original_value=data,
            sanitized_value=sanitized_dict,
            rules_applied=list(set(rules_applied)),
            warnings=warnings,
            errors=errors,
            is_valid=len(errors) == 0
        )
    
    def sanitize_list(self, data: List[Any]) -> SanitizationResult:
        """
        Sanitize list data.
        
        Args:
            data: List to sanitize
            
        Returns:
            SanitizationResult with sanitized list
        """
        rules_applied = []
        warnings = []
        errors = []
        
        # Check list length
        if len(data) > self.max_list_length:
            data = data[:self.max_list_length]
            warnings.append(f"List truncated to {self.max_list_length} items")
            rules_applied.append("list_length_truncation")
        
        sanitized_list = []
        for item in data:
            item_result = self.sanitize_data(item)
            sanitized_list.append(item_result.sanitized_value)
            rules_applied.extend(item_result.rules_applied)
            warnings.extend(item_result.warnings)
            errors.extend(item_result.errors)
        
        return SanitizationResult(
            original_value=data,
            sanitized_value=sanitized_list,
            rules_applied=list(set(rules_applied)),
            warnings=warnings,
            errors=errors,
            is_valid=len(errors) == 0
        )
    
    def sanitize_primitive(self, data: Union[int, float, bool]) -> SanitizationResult:
        """
        Sanitize primitive data types.
        
        Args:
            data: Primitive value to sanitize
            
        Returns:
            SanitizationResult with sanitized primitive
        """
        # Primitives are generally safe, but validate ranges
        warnings = []
        errors = []
        
        if isinstance(data, (int, float)):
            # Check for extreme values
            if abs(data) > 1e15:
                warnings.append("Extremely large numeric value detected")
        
        return SanitizationResult(
            original_value=data,
            sanitized_value=data,
            rules_applied=[],
            warnings=warnings,
            errors=errors,
            is_valid=True
        )
    
    def sanitize_email(self, email: str) -> SanitizationResult:
        """Sanitize email address"""
        if not isinstance(email, str):
            email = str(email)
        
        original_email = email
        rules_applied = []
        
        # Basic text sanitization
        text_result = self.sanitize_text(email)
        email = text_result.sanitized_value
        rules_applied.extend(text_result.rules_applied)
        
        # Email-specific validation
        is_valid, error_msg = self.validation_rules["email_format"].validate(email)
        
        return SanitizationResult(
            original_value=original_email,
            sanitized_value=email,
            rules_applied=rules_applied,
            errors=[error_msg] if not is_valid else [],
            is_valid=is_valid
        )
    
    def sanitize_ip_address(self, ip: str) -> SanitizationResult:
        """Sanitize IP address"""
        if not isinstance(ip, str):
            ip = str(ip)
        
        original_ip = ip
        rules_applied = []
        
        # Remove whitespace
        ip = ip.strip()
        rules_applied.append("whitespace_removal")
        
        # Validate IP format
        is_valid, error_msg = self.validation_rules["ip_address"].validate(ip)
        
        return SanitizationResult(
            original_value=original_ip,
            sanitized_value=ip,
            rules_applied=rules_applied,
            errors=[error_msg] if not is_valid else [],
            is_valid=is_valid
        )
    
    def sanitize_url(self, url: str) -> SanitizationResult:
        """Sanitize URL"""
        if not isinstance(url, str):
            url = str(url)
        
        original_url = url
        rules_applied = []
        warnings = []
        
        # Basic text sanitization (but preserve URL structure)
        url = url.strip()
        rules_applied.append("whitespace_removal")
        
        # URL encoding for safety
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                # Reconstruct with proper encoding
                url = urllib.parse.urlunparse(parsed)
                rules_applied.append("url_encoding")
        except Exception:
            warnings.append("URL parsing failed, treating as plain text")
        
        # Validate URL format
        is_valid, error_msg = self.validation_rules["url_format"].validate(url)
        
        return SanitizationResult(
            original_value=original_url,
            sanitized_value=url,
            rules_applied=rules_applied,
            warnings=warnings,
            errors=[error_msg] if not is_valid else [],
            is_valid=is_valid
        )
    
    def sanitize_filename(self, filename: str) -> SanitizationResult:
        """Sanitize filename"""
        if not isinstance(filename, str):
            filename = str(filename)
        
        original_filename = filename
        rules_applied = []
        
        # Remove path separators and dangerous characters
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', filename)
        rules_applied.append("dangerous_chars_removal")
        
        # Remove path traversal
        filename = filename.replace('..', '')
        rules_applied.append("path_traversal_removal")
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
            rules_applied.append("length_truncation")
        
        # Ensure not empty
        if not filename.strip():
            filename = "sanitized_filename"
            rules_applied.append("empty_filename_replacement")
        
        return SanitizationResult(
            original_value=original_filename,
            sanitized_value=filename.strip(),
            rules_applied=rules_applied,
            is_valid=True
        )
    
    def sanitize_user_id(self, user_id: str) -> SanitizationResult:
        """Sanitize user ID"""
        if not isinstance(user_id, str):
            user_id = str(user_id)
        
        original_user_id = user_id
        rules_applied = []
        
        # Allow only alphanumeric, hyphens, underscores
        user_id = re.sub(r'[^a-zA-Z0-9\-_]', '', user_id)
        rules_applied.append("alphanumeric_only")
        
        # Length limits
        if len(user_id) > 64:
            user_id = user_id[:64]
            rules_applied.append("length_truncation")
        
        is_valid = len(user_id) > 0
        
        return SanitizationResult(
            original_value=original_user_id,
            sanitized_value=user_id,
            rules_applied=rules_applied,
            errors=["User ID cannot be empty"] if not is_valid else [],
            is_valid=is_valid
        )
    
    def sanitize_event_id(self, event_id: str) -> SanitizationResult:
        """Sanitize event ID"""
        return self.sanitize_user_id(event_id)  # Same rules as user ID
    
    def sanitize_timestamp(self, timestamp: Union[str, datetime]) -> SanitizationResult:
        """Sanitize timestamp"""
        original_timestamp = timestamp
        rules_applied = []
        errors = []
        
        if isinstance(timestamp, datetime):
            # Convert to ISO format
            sanitized_value = timestamp.isoformat()
            rules_applied.append("datetime_to_iso")
        elif isinstance(timestamp, str):
            try:
                # Try to parse and reformat
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                sanitized_value = dt.isoformat()
                rules_applied.append("timestamp_normalization")
            except ValueError:
                sanitized_value = timestamp
                errors.append("Invalid timestamp format")
        else:
            sanitized_value = str(timestamp)
            errors.append("Timestamp must be string or datetime")
        
        return SanitizationResult(
            original_value=original_timestamp,
            sanitized_value=sanitized_value,
            rules_applied=rules_applied,
            errors=errors,
            is_valid=len(errors) == 0
        )
    
    def sanitize_json(self, json_data: Union[str, Dict, List]) -> SanitizationResult:
        """Sanitize JSON data"""
        original_data = json_data
        rules_applied = []
        errors = []
        
        if isinstance(json_data, str):
            # Parse JSON string
            try:
                parsed_data = json.loads(json_data)
                # Recursively sanitize the parsed data
                result = self.sanitize_data(parsed_data)
                # Convert back to JSON string
                sanitized_value = json.dumps(result.sanitized_value, ensure_ascii=False)
                rules_applied.extend(["json_parse", "recursive_sanitization", "json_serialize"])
                rules_applied.extend(result.rules_applied)
                errors.extend(result.errors)
            except json.JSONDecodeError as e:
                sanitized_value = json_data
                errors.append(f"JSON parsing error: {str(e)}")
        else:
            # Already parsed, just sanitize recursively
            result = self.sanitize_data(json_data)
            sanitized_value = result.sanitized_value
            rules_applied.extend(["recursive_sanitization"])
            rules_applied.extend(result.rules_applied)
            errors.extend(result.errors)
        
        return SanitizationResult(
            original_value=original_data,
            sanitized_value=sanitized_value,
            rules_applied=rules_applied,
            errors=errors,
            is_valid=len(errors) == 0
        )
    
    def sanitize_command(self, command: str) -> SanitizationResult:
        """Sanitize command string with extra security"""
        if not isinstance(command, str):
            command = str(command)
        
        original_command = command
        rules_applied = []
        warnings = ["Command sanitization applied - review for security"]
        
        # Apply all security rules aggressively
        text_result = self.sanitize_text(command)
        command = text_result.sanitized_value
        rules_applied.extend(text_result.rules_applied)
        
        # Additional command-specific sanitization
        command = re.sub(r'[;&|`$(){}[\]\\]', '', command)
        rules_applied.append("command_injection_chars_removal")
        
        return SanitizationResult(
            original_value=original_command,
            sanitized_value=command,
            rules_applied=rules_applied,
            warnings=warnings,
            is_valid=True
        )
    
    def sanitize_file_path(self, file_path: str) -> SanitizationResult:
        """Sanitize file path"""
        if not isinstance(file_path, str):
            file_path = str(file_path)
        
        original_path = file_path
        rules_applied = []
        
        # Remove null bytes
        file_path = file_path.replace('\x00', '')
        rules_applied.append("null_byte_removal")
        
        # Remove path traversal
        file_path = re.sub(r'\.\./', '', file_path)
        file_path = re.sub(r'\.\.\\', '', file_path)
        rules_applied.append("path_traversal_removal")
        
        # Normalize path separators
        file_path = file_path.replace('\\', '/')
        rules_applied.append("path_separator_normalization")
        
        # Remove dangerous sequences
        file_path = re.sub(r'/+', '/', file_path)  # Multiple slashes
        rules_applied.append("multiple_slash_removal")
        
        return SanitizationResult(
            original_value=original_path,
            sanitized_value=file_path,
            rules_applied=rules_applied,
            is_valid=True
        )
    
    def _detect_field_type(self, field_name: str) -> Optional[str]:
        """Detect field type from field name"""
        field_name_lower = field_name.lower()
        
        type_mappings = {
            'email': 'email',
            'ip': 'ip_address',
            'url': 'url',
            'filename': 'filename',
            'user': 'user_id',
            'userid': 'user_id',
            'event': 'event_id',
            'eventid': 'event_id',
            'timestamp': 'timestamp',
            'time': 'timestamp',
            'json': 'json_data',
            'data': 'json_data',
            'description': 'description',
            'message': 'message',
            'command': 'command',
            'path': 'file_path',
            'filepath': 'file_path'
        }
        
        for pattern, field_type in type_mappings.items():
            if pattern in field_name_lower:
                return field_type
        
        return None
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        try:
            name, addr = parseaddr(email)
            return '@' in addr and '.' in addr.split('@')[1]
        except Exception:
            return False
    
    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _validate_json(self, json_str: str) -> bool:
        """Validate JSON format"""
        try:
            json.loads(json_str)
            return True
        except (json.JSONDecodeError, TypeError):
            return False
    
    def _validate_base64(self, data: str) -> bool:
        """Validate Base64 format"""
        try:
            base64.b64decode(data, validate=True)
            return True
        except Exception:
            return False
    
    def add_sanitization_rule(self, name: str, pattern: str, replacement: str = "", description: str = "") -> None:
        """Add custom sanitization rule"""
        self.sanitization_rules[name] = SanitizationRule(
            name=name,
            pattern=re.compile(pattern, re.IGNORECASE),
            replacement=replacement,
            description=description
        )
    
    def add_validation_rule(self, name: str, validator: Callable[[Any], bool], error_message: str, description: str = "") -> None:
        """Add custom validation rule"""
        self.validation_rules[name] = ValidationRule(
            name=name,
            validator=validator,
            error_message=error_message,
            description=description
        )
    
    def add_field_processor(self, field_type: str, processor: Callable[[Any], SanitizationResult]) -> None:
        """Add custom field processor"""
        self.field_processors[field_type] = processor
    
    def get_sanitization_report(self) -> Dict[str, Any]:
        """Get report of available sanitization capabilities"""
        return {
            "sanitization_rules": {
                name: {
                    "description": rule.description,
                    "pattern": rule.pattern.pattern
                }
                for name, rule in self.sanitization_rules.items()
            },
            "validation_rules": {
                name: {
                    "description": rule.description,
                    "required": rule.required,
                    "error_message": rule.error_message
                }
                for name, rule in self.validation_rules.items()
            },
            "field_processors": list(self.field_processors.keys()),
            "configuration": {
                "max_string_length": self.max_string_length,
                "max_list_length": self.max_list_length,
                "max_dict_depth": self.max_dict_depth,
                "enable_html_sanitization": self.enable_html_sanitization,
                "enable_sql_injection_protection": self.enable_sql_injection_protection,
                "enable_xss_protection": self.enable_xss_protection,
                "strict_mode": self.strict_mode
            }
        }