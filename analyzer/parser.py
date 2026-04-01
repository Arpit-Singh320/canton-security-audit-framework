import re
import os
from typing import List, Dict, Any

class DamlChoice:
    """Represents a parsed choice from a Daml template."""
    def __init__(self, name: str, line: int, controllers: List[str], body: str):
        self.name = name
        self.line = line
        self.controllers = controllers
        self.body = body

    def to_dict(self) -> Dict[str, Any]:
        """Converts the object to a dictionary for serialization."""
        return {
            "name": self.name,
            "line": self.line,
            "controllers": self.controllers,
            "body": self.body,
        }

class DamlTemplate:
    """Represents a parsed template from a Daml file."""
    def __init__(self, name: str, file_path: str, line: int, signatories: List[str], observers: List[str], choices: List[DamlChoice]):
        self.name = name
        self.file_path = file_path
        self.line = line
        self.signatories = signatories
        self.observers = observers
        self.choices = choices

    def to_dict(self) -> Dict[str, Any]:
        """Converts the object to a dictionary for serialization."""
        return {
            "name": self.name,
            "file_path": self.file_path,
            "line": self.line,
            "signatories": self.signatories,
            "observers": self.observers,
            "choices": [choice.to_dict() for choice in self.choices],
        }

class DamlParser:
    """
    Parses a .daml file to extract an Abstract Syntax Tree (AST)-like structure,
    focusing on templates, choices, and their key properties.

    This parser uses regular expressions and is designed for common Daml patterns.
    It may not cover all edge cases of complex Daml syntax.
    """

    def __init__(self, file_path: str):
        """
        Initializes the parser with the path to a Daml file.
        
        Args:
            file_path: The path to the .daml file.
        
        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Daml file not found: {file_path}")
        self.file_path = file_path
        with open(file_path, 'r', encoding='utf-8') as f:
            self.content = f.read()

    def parse(self) -> List[DamlTemplate]:
        """
        Parses the entire Daml file and returns a list of found templates.
        
        Returns:
            A list of DamlTemplate objects representing the parsed structures.
        """
        # Regex to capture top-level templates. It looks for 'template ... where'
        # and captures the content until the next template or end of file.
        template_regex = re.compile(
            r"^\s*template\s+(?P<name>\w+)"
            r"[\s\S]*?" # Non-greedily consume the 'with' block
            r"where(?P<where_block>[\s\S]*?)"
            r"(?=\n\s*template|\Z)",
            re.MULTILINE
        )

        parsed_templates = []
        for match in template_regex.finditer(self.content):
            where_block = match.group("where_block")
            where_block_start_index = match.start("where_block")

            template = DamlTemplate(
                name=match.group("name"),
                file_path=self.file_path,
                line=self._get_line_number(match.start()),
                signatories=self._extract_parties('signatory', where_block),
                observers=self._extract_parties('observer', where_block),
                choices=self._parse_choices(where_block, where_block_start_index)
            )
            parsed_templates.append(template)
            
        return parsed_templates

    def _get_line_number(self, char_index: int) -> int:
        """Calculates the line number for a given character index in the file content."""
        return self.content[:char_index].count('\n') + 1

    def _extract_parties(self, keyword: str, block: str) -> List[str]:
        """
        Extracts party expressions from signatory or observer lines.
        Handles optional end-of-line comments.
        """
        pattern = re.compile(rf"^\s*{keyword}\s+(.*?)(?:\s*--.*)?$", re.MULTILINE)
        match = pattern.search(block)
        if match:
            # This is a simplification. It splits by comma but doesn't parse
            # complex Daml expressions. It returns the raw expression strings.
            parties_str = match.group(1).strip()
            return [p.strip() for p in parties_str.split(',')]
        return []

    def _parse_choices(self, where_block: str, where_block_offset: int) -> List[DamlChoice]:
        """Parses all choices within a template's 'where' block."""
        choices = []
        # Regex to find a choice's name, its controller list, and the 'do' keyword.
        choice_regex = re.compile(
            r"^\s*choice\s+(?P<name>\w+)"
            r"[\s\S]*?"  # Non-greedy match for params, return type, etc.
            r"^\s*controller\s+(?P<controllers>.*?)(?:\s*--.*)?\n"
            r"^\s*do\b",
            re.MULTILINE
        )
        
        for match in choice_regex.finditer(where_block):
            # Calculate absolute positions relative to the full file content
            absolute_match_start = where_block_offset + match.start()
            absolute_body_start = where_block_offset + match.end()
            
            controllers_str = match.group("controllers").strip()
            
            choice = DamlChoice(
                name=match.group("name"),
                line=self._get_line_number(absolute_match_start),
                controllers=[p.strip() for p in controllers_str.split(',')],
                body=self._extract_indented_block(absolute_body_start)
            )
            choices.append(choice)
            
        return choices

    def _extract_indented_block(self, start_index: int) -> str:
        """
        Extracts a complete indented block (e.g., a 'do' block) from the main
        file content, starting from a given character index.
        """
        text_after_keyword = self.content[start_index:]
        lines = text_after_keyword.splitlines()
        
        block_indent = -1
        first_content_line_index = -1

        # Find the indentation of the first non-empty line to define the block's level
        for i, line in enumerate(lines):
            if line.strip():
                match = re.match(r'^(\s*)', line)
                block_indent = len(match.group(1)) if match else 0
                first_content_line_index = i
                break
        
        if block_indent == -1:
            return "" # Block is empty

        # Now, collect all subsequent lines that belong to the block
        block_lines = []
        for line in lines[first_content_line_index:]:
            if not line.strip():
                block_lines.append(line)
                continue

            match = re.match(r'^(\s*)', line)
            current_indent = len(match.group(1)) if match else 0

            if current_indent >= block_indent:
                block_lines.append(line)
            else:
                break # Indentation decreased, block has ended
        
        # Un-indent the collected lines for a clean representation of the body
        unindented_lines = []
        for line in block_lines:
            if line.strip() and len(line) >= block_indent:
                unindented_lines.append(line[block_indent:])
            else:
                unindented_lines.append(line)
        
        return "\n".join(unindented_lines)