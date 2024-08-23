import numbers
import pandas as pd

import networkx as nx
grammar = {
  "grammar": {
    "expression": [
      "||",
      "&&",
      "if-then-else",
      "has",
      "like",
      "+",
      "-",
      "*",
      "!",
      "neg",
      ".",
      "call",
      "Set",
      "Record",
      "bool-literal",
      "string-literal",
      "num-literal",
      "principal",
      "action",
      "resource",
      "context",
      "entity uid"
    ]
  },
  "terminals": [
    "principal",
    "action",
    "resource",
    "context",
    "entity uid",
    "bool-literal",
    "string-literal",
    "num-literal"
  ]
}
unary_subexprs = set(["!", "neg"])
binary_subexprs = set(["==", "!=", "in", "<", "<=", ">",">=", "&&", "||", "+", "-", "*", "contains", "containsAll", "containsAny"])
lhs_only_subexprs = set(["like", ".", "has", "is"])
decimal_ops = set([
    "greaterThanOrEqual",
    "greaterThan",
    "lessThan",
    "lessThanOrEqual"
])
literals = set(["bool-literal", "string-literal", "num-literal", "entity uid"])
ip_ops = set(["isIpv4", "isIpv6", "isInRange", "isLoopback", "isMulticast"])

CATEGORIES = {
    # "Unary Ops": unary_subexprs,
    # "Binary Ops": binary_subexprs,
    # "Literals": literals,
    # "IP Ops": ip_ops,
    # "Decimal Ops": decimal_ops
}

def get_descriptor_key(v):
    return list(v.keys())[0]


def extract_value_kind(v):
    val_kind = v.get("Value")
    if isinstance(val_kind, bool):
        return "bool-literal"
    elif isinstance(val_kind, str):
        return "string-literal"
    elif isinstance(val_kind, (int, float, complex)):
        return "num-literal"
    else:
        return None

def get_expr_kind(v):
    key = get_descriptor_key(v)
    if key == "Value":
        kind = extract_value_kind(v)
    else:
        kind = key
    return kind

def get_category(kind):
    for key, value in CATEGORIES.items():
        if kind in value:
            return key
    return kind

def get_category_map(v):
    all_subexprs = subexprs(v)
    cats = [get_category(get_expr_kind(e)) for e in all_subexprs]
    return {i:cats.count(i) for i in set(cats)}


def subexprs(v):
    descriptor = get_descriptor_key(v)
    subexpr = None
    if descriptor == "Value" or descriptor == "Var" or descriptor == "Slot" or descriptor == "Unknown":
        subexpr = []
    elif descriptor in unary_subexprs:
        subexpr = unary_subexpr(v)
    elif descriptor in binary_subexprs:
        subexpr = binary_subexpr(v)    
    elif descriptor in lhs_only_subexprs:
        subexpr = lhs_only_subexpr(v)
    elif descriptor == "if-then-else":
        subexpr = ite_subexpr(v)
    elif descriptor == "Set":
        subexpr = set_subexpr(v)
    elif descriptor == "Record":
        subexpr = record_subexpr(v)
    else:
        subexpr = extension_call_subexpr(v)
    subexpr.append(v)
    return subexpr

def unary_subexpr(v):
    key = get_descriptor_key(v)
    obj = v[key]["arg"]
    return subexprs(obj)

def binary_subexpr(v):
    obj = v[get_descriptor_key(v)]
    left = subexprs(obj["left"])
    right = subexprs(obj["right"])
    left.extend(right)
    return left

def lhs_only_subexpr(v):
    obj = v[get_descriptor_key(v)]
    return subexprs(obj["left"])

def ite_subexpr(v):
    obj = v[get_descriptor_key(v)]
    condition = subexprs(obj["if"])
    consequent = subexprs(obj["then"])
    alternative = subexprs(obj["else"])
    condition.extend(consequent)
    condition.extend(alternative)
    return condition

def set_subexpr(v):
    arr = v["Set"]
    iter_result = [subexprs(item) for item in arr if item]
    return [item for sublist in iter_result for item in sublist]

def record_subexpr(v):
    internal = v["Record"]
    t = [subexprs(obj) for obj in internal.values() if obj]
    return [item for sublist in t for item in sublist]

def extension_call_subexpr(v):
    args = v[get_descriptor_key(v)]
    iter_result = [subexprs(item) for item in args if item]
    return [item for sublist in iter_result for item in sublist]


def children(v):
    descriptor = get_descriptor_key(v)
    children = None
    if descriptor == "Value" or descriptor == "Var" or descriptor == "Slot" or descriptor == "Unknown":
        children = []
    elif descriptor in unary_subexprs:
        children = unary_child(v)
    elif descriptor in binary_subexprs:
        children = binary_child(v)    
    elif descriptor in lhs_only_subexprs:
        children = lhs_only_child(v)
    elif descriptor == "if-then-else":
        children = ite_child(v)
    elif descriptor == "Set":
        children = set_child(v)
    elif descriptor == "Record":
        children = record_child(v)
    else:
        children = extension_call_child(v)
    return children

def unary_child(v):
    key = get_descriptor_key(v)
    obj = v[key]["arg"]
    return [obj]

def binary_child(v):
    obj = v[get_descriptor_key(v)]
    return [obj["left"], obj["right"]]

def lhs_only_child(v):
    obj = v[get_descriptor_key(v)]
    return [obj["left"]]

def ite_child(v):
    obj = v[get_descriptor_key(v)]
    return [obj["if"], obj["then"], obj["else"]]

def set_child(v):
    arr = v["Set"]
    return [item for item in arr if item]

def record_child(v):
    internal = v["Record"]
    return list(internal.values())

def extension_call_child(v):
    args = v[get_descriptor_key(v)]
    return [item for item in args if item]

def construct_graph(G, expr):
    key = get_descriptor_key(expr)
    G.add_node(key)
    for child in children(expr):
        construct_graph(G, child)
        G.add_edge(key, get_descriptor_key(child))

def est_to_graph(est):
    G = nx.DiGraph()
    construct_graph(G, est)
    return G    

def find_paths(G, node, k):
    if k == 0:
        return [[node]]
    paths = [[node] + path for neighbor in G.neighbors(node) for path in find_paths(G, neighbor, k - 1) if node not in path]
    return paths

def find_all_paths(G, node, k):
    allpaths = []
    for node in G:
        allpaths.extend(find_paths(G, node, k))
    return allpaths

#[metric("Count", "Count of sub exprs", "Count", "# of expressions")]

def count_size(est):
    est_subexpr = subexprs(est)
    return len(est_subexpr)

def expr_kinds(est):
    est_subexpr = subexprs(est)
    expr_kinds = [get_expr_kind(v) for v in est_subexpr]
    return expr_kinds

#TODO: k-path coverage
def num_kpaths(est, k=2):
    G = est_to_graph(est)
    return len(find_all_paths(G, est, k))

def load_json_df(df_file):
    df = pd.read_json(open(df_file, "r"), lines=True)
    return df

def load_eval_df(df):
    df["entities"] = df["representation"].apply(lambda x: json.loads(x)["entities"] if x else "")
    df["request"] = df["representation"].apply(lambda x: json.loads(x)["request"] if x else "")
    df["expression"] = df["representation"].apply(lambda x: json.loads(x)["expression"] if x else "")
    return df

def load_policy_df(df):
    df["policy"] = df["representation"].apply(lambda x: json.loads(x)["policy"] if x else "")
    return df

def load_abac_df(df):
    df["entities"] = df["representation"].apply(lambda x: json.loads(x)["entities"] if x else "")
    df["requests"] = df["representation"].apply(lambda x: json.loads(x)["requests"] if x else "")
    df["policy"] = df["representation"].apply(lambda x: json.loads(x)["policy"] if x else "")
    return df

def load_validation_df(df):
    df["schema"] = df["representation"].apply(lambda x: json.loads(x)["schema"] if x else "")
    df["policy"] = df["representation"].apply(lambda x: json.loads(x)["policy"] if x else "")
    return df