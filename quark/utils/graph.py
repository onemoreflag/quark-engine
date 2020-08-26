from graphviz import Digraph


def call_graph(first_wrappers_list, second_wrappers_list,
               mutual_parent_function=None,
               crime_description=None,
               permission=None,
               register_object=None,
               filename="quark_call_graph"):
    # Convert MUTF8String to string
    first_wrappers_list = [str(x) for x in first_wrappers_list]
    second_wrappers_list = [str(x) for x in second_wrappers_list]

    # Initialize the Digraph object
    dot = Digraph(filename=filename,
                  node_attr={"fontname": "Courier New Bold"},
                  comment="Quark-Engine Call Graph Result",
                  format="svg",
                  graph_attr={"label": crime_description},
                  )

    # Build the nodes
    for method_name in first_wrappers_list:
        dot.node(method_name, label=method_name, shape="record", style="rounded")

    for method_name in second_wrappers_list:
        dot.node(method_name, label=method_name, shape="record", style="rounded")

    # mutual parent function node
    dot.node(mutual_parent_function, label=mutual_parent_function, shape="box")
    # permission node
    dot.node("permission", label="\n".join(permission))
    # register node
    dot.node("register", label=str(register_object).replace(",", "\n"))

    # Build the edges

    # register object -> mutual parent function
    dot.edge("register", mutual_parent_function)

    # mutual parent function -> the first node of each node
    dot.edge(mutual_parent_function, first_wrappers_list[-1], "calls")
    dot.edge(mutual_parent_function, second_wrappers_list[-1], "calls")

    # wrapper -> wrapper
    for i in range(len(first_wrappers_list) - 1, 0, -1):
        dot.edge(first_wrappers_list[i], first_wrappers_list[i - 1], "calls")
    # wrapper -> wrapper
    for i in range(len(second_wrappers_list) - 1, 0, -1):
        dot.edge(second_wrappers_list[i], second_wrappers_list[i - 1], "calls")
    # the last node of each node -> permission
    dot.edge(first_wrappers_list[0], "permission", "request")
    dot.edge(second_wrappers_list[0], "permission", "request")

    # show the image
    dot.view()


if __name__ == '__main__':
    # usage
    first_method_list = ["method_1", "method_2", "method_3"]
    second_method_list = ["method_1", "method_2", "method_3"]
    call_graph(first_method_list, second_method_list, crime_description="send location via SMS",
               mutual_parent_function="sendMessage")
