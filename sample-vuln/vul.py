
# --- VULN 7: Dangerous eval on user input ---
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    # PRECOGS_FIX: replace eval with a safe arithmetic evaluator using ast
    import ast
    import operator as op

    # supported operators
    allowed_operators = {
        ast.Add: op.add,
        ast.Sub: op.sub,
        ast.Mult: op.mul,
        ast.Div: op.truediv,
        ast.Mod: op.mod,
        ast.Pow: op.pow,
        ast.FloorDiv: op.floordiv,
        ast.USub: op.neg,
        ast.UAdd: op.pos,
    }

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value
            raise ValueError("Only numeric constants are allowed")
        if isinstance(node, ast.Num):  # Python <3.8
            return node.n
        if isinstance(node, ast.BinOp):
            left = _eval(node.left)
            right = _eval(node.right)
            op_type = type(node.op)
            if op_type in allowed_operators:
                return allowed_operators[op_type](left, right)
            raise ValueError("Operator not allowed")
        if isinstance(node, ast.UnaryOp):
            op_type = type(node.op)
            if op_type in allowed_operators:
                return allowed_operators[op_type](_eval(node.operand))
            raise ValueError("Unary operator not allowed")
        raise ValueError("Unsupported expression")

    try:
        parsed = ast.parse(expr, mode="eval")
        result = _eval(parsed)
        return {"expr": expr, "result": result}
    except Exception as e:
        return {"error": str(e)}, 400