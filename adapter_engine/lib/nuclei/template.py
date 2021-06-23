import re

from adapter_engine.lib.nuclei.filter import FilterExpression
from enum import Enum

# 定义标识
FILTER_SEPARATOR = '|'
FILTER_ARGUMENT_SEPARATOR = ':'
VARIABLE_ATTRIBUTE_SEPARATOR = '.'
BLOCK_TAG_START = '{%'
BLOCK_TAG_END = '%}'
VARIABLE_TAG_START = '{{'
VARIABLE_TAG_END = '}}'
COMMENT_TAG_START = '{#'
COMMENT_TAG_END = '#}'
TRANSLATOR_COMMENT_MARK = 'Translators'
SINGLE_BRACE_START = '{'
SINGLE_BRACE_END = '}'
UNKNOWN_SOURCE = '<unknown source>'


class TemplateSyntaxError(Exception):
    pass


class Node:
    must_be_first = False
    token = None

    def render(self, context):
        pass

    def render_annotated(self, context):
        return self.render(context)

    def __iter__(self):
        yield self


class TextNode(Node):
    def __init__(self, s):
        self.s = s

    def __repr__(self):
        return "<%s: %r>" % (self.__class__.__name__, self.s[:25])

    def render(self, context):
        return self.s


class VariableNode(Node):
    def __init__(self, filter_expression):
        self.filter_expression = filter_expression

    def __repr__(self):
        return "<Variable Node: %s>" % self.filter_expression

    def render(self, context):
        try:
            output = self.filter_expression.resolve(context)
        except UnicodeDecodeError:
            return ''
        return output


class NodeList(list):
    contains_non_text = False

    def render(self, context):
        bits = []
        for node in self:
            if isinstance(node, VariableNode):  # 替换变量占位符
                bit = node.render(context)
            elif isinstance(node, TextNode):  # 替换文本占位符
                bit = node.render(context)
            else:
                bit = node
            bits.append(str(bit))
        return ''.join(bits)


class TokenType(Enum):
    TEXT = 0
    VAR = 1
    BLOCK = 2
    COMMENT = 3


class Token:
    def __init__(self, token_type, contents, position=None, line_no=None):
        self.token_type, self.contents = token_type, contents
        self.line_no = line_no
        self.position = position

    def __str__(self):
        token_name = self.token_type.name.capitalize()
        return ('<%s token: "%s...">' %
                (token_name, self.contents[:20].replace('\n', '')))


class Parser:
    def __init__(self, tokens, libraries=None, builtins=None):
        self.tokens = list(reversed(tokens))
        self.tags = {}
        self.filters = {}
        self.command_stack = []
        self.variable_node = []

        if libraries is None:
            libraries = {}
        if builtins is None:
            builtins = []

        self.libraries = libraries
        for builtin in builtins:
            self.add_library(builtin)

    def compile_filter(self, token):
        return FilterExpression(token, self)

    def parse(self):
        nodelist = NodeList()
        while self.tokens:
            token = self.tokens.pop()
            if token.token_type.value == 0:  # 纯文本
                self.extend_node_list(nodelist, TextNode(token.contents), token)
            elif token.token_type.value == 1:  # 变量
                filter_expression = self.compile_filter(token.contents)
                var_node = VariableNode(filter_expression)
                self.variable_node.append(str(filter_expression))
                self.extend_node_list(nodelist, var_node, token)

        return nodelist

    def extend_node_list(self, nodelist, node, token):
        if isinstance(nodelist, NodeList) and not isinstance(node, TextNode):
            nodelist.contains_non_text = True
        node.token = token
        nodelist.append(node)

    def add_library(self, lib):
        self.tags.update(lib.tags)
        self.filters.update(lib.filters)

    def find_filter(self, filter_name):
        if filter_name in self.filters:
            return self.filters[filter_name]
        else:
            raise TemplateSyntaxError("Invalid filter: '%s'" % filter_name)


class Lexer:
    def __init__(self, template_string):
        self.template_string = template_string
        self.verbatim = False

    def tokenize(self):
        tag_re = re.compile(r'({%.*?%}|{{.*?}}|{#.*?#}|{§.*?§})')  # 分割符{{}},{%%},{##}
        in_tag = False
        line_no = 1
        result = []
        for bit in tag_re.split(self.template_string):
            if bit:
                result.append(self.create_token(bit, None, line_no, in_tag))
            in_tag = not in_tag
            line_no += bit.count('\n')
        return result

    def create_token(self, token_string, position, line_no, in_tag):  # 根据分割出来的节点生成对应的类型，in_tag为占位符
        if in_tag and not self.verbatim:  # 其他的节点
            if token_string.startswith(VARIABLE_TAG_START):  # 变量{{}}
                return Token(TokenType.VAR, token_string[2:-2].strip(), position, line_no)
        else:
            return Token(TokenType.TEXT, token_string, position, line_no)  # 其他的都是纯文本


class Template:
    def __init__(self, template_string, name=None):
        self.name = name
        self.source = str(template_string)
        self.variable_node = []  # 占位符
        self.nodelist = self.compile_nodelist()  # 解析模板节点块

    def __iter__(self):
        for node in self.nodelist:
            yield from node

    def _render(self, context):
        return self.nodelist.render(context)

    def render(self, context):
        return self._render(context)

    def compile_nodelist(self):
        lexer = Lexer(self.source)
        tokens = lexer.tokenize()  # 标志token列表
        parser = Parser(tokens)
        p = parser.parse()
        self.variable_node = parser.variable_node
        return p
