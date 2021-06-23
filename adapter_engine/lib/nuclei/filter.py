import ast
import sys
from _ast import Attribute, Expr, Assign
from typing import Any


class FilterFunc:
    @staticmethod
    def len(arg):
        return len(arg)


class NodeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.filter = {'type': ''}
        self.flag = True  # 为假说明已经找到入口

    def visit_Name(self, node):
        if self.flag is None and self.flag != sys._getframe().f_code.co_name:
            self.flag = sys._getframe().f_code.co_name
        v_id, v_ctx = node.id, node.ctx
        if isinstance(v_ctx, ast.Load):
            if self.flag != sys._getframe().f_code.co_name:
                return {'type': 'name', 'name': v_id}

        self.filter.update({'type': 'name', 'name': v_id})

    def visit_Constant(self, node):
        if self.flag is None and self.flag != sys._getframe().f_code.co_name:
            self.flag = sys._getframe().f_code.co_name
        if self.flag != sys._getframe().f_code.co_name:
            return {'type': 'constant', 'name': node.value}
        self.filter.update({'type': 'constant', 'name': node.value})

    def visit_Call(self, node):
        func = None
        if self.flag is None and self.flag != sys._getframe().f_code.co_name:
            self.flag = sys._getframe().f_code.co_name
        if isinstance(node.func, ast.Name):
            func = self.visit_Name(node.func)
        elif isinstance(node.func, ast.Constant):
            func = self.visit_Constant(node.func)
        elif isinstance(node.func, ast.Attribute):
            func = self.visit_Attribute(node.func)
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                arg_name = self.visit_Name(arg)
                args.append(arg_name)
            elif isinstance(arg, ast.Constant):
                arg_name = self.visit_Constant(arg)
                args.append(arg_name)
            elif isinstance(arg, ast.Attribute):
                arg_name = self.visit_Attribute(arg)
                args.append(arg_name)
            # elif isinstance(arg, ast.Call):
            #     arg_name = self.visit_Call(arg)
            #     args.append(arg_name)
        keywords = []
        for keyword in node.keywords:
            arg, value = keyword.arg, keyword.value
            if isinstance(value, ast.Name):
                value_name = self.visit_Name(value)
                keywords.append({'arg': arg, 'value': value_name})
            elif isinstance(value, ast.Constant):
                value_name = self.visit_Constant(value)
                keywords.append({'arg': arg, 'value': value_name})
        if self.flag != sys._getframe().f_code.co_name:
            return {'type': 'call', 'func': func, 'args': args, 'keywords': keywords}

    def visit_Attribute(self, node: Attribute) -> Any:
        if self.flag is None and self.flag != sys._getframe().f_code.co_name:
            self.flag = sys._getframe().f_code.co_name
        if self.flag != sys._getframe().f_code.co_name:
            if isinstance(node.value, ast.Name):
                value, attr = node.value, node.attr
                value_name = self.visit_Name(value)
                return {'type': 'attr', **value_name, 'attr': attr}

    def visit_Expr(self, node: Expr) -> Any:
        if self.flag is None and self.flag != sys._getframe().f_code.co_name:
            self.flag = sys._getframe().f_code.co_name
        if isinstance(node.value, ast.Constant):
            constant = self.visit_Constant(node.value)
            self.filter.update(constant, **{'type': 'constant'})
        elif isinstance(node.value, ast.Name):  # 变量
            name = self.visit_Name(node.value)
            self.filter.update(name, **{'type': 'name'})
        elif isinstance(node.value, ast.Call):
            call = self.visit_Call(node.value)
            self.filter.update(call)
        elif isinstance(node.value, ast.Attribute):
            attr = self.visit_Attribute(node.value)
            self.filter.update(attr)

    def visit_Assign(self, node: Assign) -> Any:
        if self.flag is None and self.flag != sys._getframe().f_code.co_name:
            self.flag = sys._getframe().f_code.co_name


class Variable:
    def __init__(self, f_type, var, filter_dict=None):  # 变量
        self.var = var
        self.literal = None
        self.filter_dict = filter_dict
        self.f_type = f_type
        self.lookups = []
        self.reload_var(var, filter_dict)

    def reload_var(self, var, filter_dict):
        if self.f_type == 'call':
            func = filter_dict.get('func')
            args = filter_dict.get('args')
            func_type = func.get('type')
            if func_type == 'name':
                func_name = func.get('name')
                self.lookups.append((func_name, args,))
                self.var = func

    def resolve(self, context):
        if self.filter_dict is not None:
            value = self._resolve_lookup(context)
        else:
            value = context.get(self.var)
        return value

    def __repr__(self):
        return "<%s: %r>" % (self.__class__.__name__, self.var)

    def _resolve_lookup(self, context):
        current = context
        for func, args in self.lookups:
            for arg in args:
                if arg['type'] == 'name' and arg.get('name') in context:
                    f_func = getattr(FilterFunc, func, None)
                    if f_func:
                        res = f_func(context[arg.get('name')])
                        current[arg.get('name')] = res
                        return res
                    else:
                        # print("找不到过滤函数")
                        return None
        return current


class FilterExpression:

    def __init__(self, token, parser):
        self.token = token
        try:
            ast_tree = ast.parse(token)
            node_visit = NodeVisitor()
            node_visit.visit(ast_tree)
            f_type, var_obj, filters = self.get_filter(node_visit.filter)
            self.filters = filters
            self.var = var_obj
        except SyntaxError:
            self.filters = []
            self.var = None

    def get_filter(self, filter_dict):
        f_type = filter_dict.get('type')
        if f_type == 'constant':  # 常量
            var_obj = Variable(f_type=f_type, var=filter_dict.get('name'), filter_dict=None).resolve({})
            return f_type, var_obj, []
        elif f_type == 'name':  # 变量
            name = filter_dict.get('name')
            var_obj = Variable(f_type=f_type, var=name, filter_dict=None)
            return f_type, var_obj, []
        else:  # 有过滤函数和其他
            var_obj = Variable(f_type=f_type, var=None, filter_dict=filter_dict)
            return f_type, var_obj, []

    def resolve(self, context):
        if isinstance(self.var, Variable):
            obj = self.var.resolve(context)
        else:
            obj = self.var
        return obj

    def __str__(self):
        return self.token
