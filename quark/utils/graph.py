from graphviz import Digraph


def call_graph(first_wrappers_list, second_wrappers_list,
               mutual_parent_function=None,
               crime_description=None,
               permission=None,
               register_object=None,
               filename="quark_call_graph",
               first_natvie_call=None,
               second_native_call=None):
    mutual_method_name = None
    mutual_class_name = None

    # Convert MUTF8String to string
    first_wrappers_list = [str(x) for x in first_wrappers_list]
    second_wrappers_list = [str(x) for x in second_wrappers_list]

    # Initialize the Digraph object
    dot = Digraph(filename=filename,
                  node_attr={"fontname": "Courier New Bold"},
                  comment="Quark-Engine Call Graph Result",
                  format="svg",
                  # graph_attr={"label": crime_description},
                  )

    with dot.subgraph(name="cluster_mutual") as mutual_parent_function_description:
        mutual_parent_function_description.attr(style="rounded", penwidth="1", fillcolor="white",
                                                fontname="Courier New", shape="box")
        mutual_parent_function_description.attr(label="Mutual Parent Function", fontname="Courier New Bold")

        # mutual parent function node
        mutual_class_name, mutual_method_name = (str(x) for x in mutual_parent_function)
        mutual_class_name.replace(";", "")
        mutual_parent_function_description.node(mutual_method_name,
                                                label=f"Class: {mutual_class_name}\nMethod: {mutual_method_name}",
                                                shape="none",
                                                fontname="Courier New")

    with dot.subgraph(name="cluster_0") as wrapper:
        wrapper.attr(label="Wrapped Functions", fontname="Courier New Bold")
        wrapper.attr(style="rounded", penwidth="1", fillcolor="red", shape="box")
        # Build the first call nodes
        for method_name in first_wrappers_list:
            wrapper.node(method_name, label=method_name, style="rounded", penwidth="1", fillcolor="white",
                         fontname="Courier New", shape="none")

        # wrapper -> wrapper
        for i in range(len(first_wrappers_list) - 1, 0, -1):
            wrapper.edge(first_wrappers_list[i], first_wrappers_list[i - 1], "calls", fontname="Courier New")

        for method_name in second_wrappers_list:
            wrapper.node(method_name, label=method_name, style="rounded", penwidth="1", fillcolor="white",
                         fontname="Courier New", shape="none")

        # wrapper -> wrapper
        for i in range(len(second_wrappers_list) - 1, 0, -1):
            wrapper.edge(second_wrappers_list[i], second_wrappers_list[i - 1], "calls", fontname="Courier New")

    with dot.subgraph(name="cluster_1") as native_call_subgraph:
        native_call_subgraph.attr(style="rounded", penwidth="1", fillcolor="white",
                                  fontname="Courier New", shape="box")
        native_call_subgraph.attr(label="Native API Calls", fontname="Courier New Bold")
        # Native API Calls
        first_native_api_class, first_native_method = first_natvie_call
        second_native_api_class, second_native_method = second_native_call
        native_call_subgraph.node(first_native_method,
                                  label=f"Class: {first_native_api_class}\nMethod: {first_native_method}",
                                  shape="none", fontname="Courier New")
        native_call_subgraph.node(second_native_method,
                                  label=f"Class: {second_native_api_class}\nMethod: {second_native_method}",
                                  shape="none", fontname="Courier New")

    # mutual parent function -> the first node of each node
    dot.edge(mutual_method_name, first_wrappers_list[-1], "First Call", fontname="Courier New")
    dot.edge(mutual_method_name, second_wrappers_list[-1], "Second Call", fontname="Courier New")

    dot.node("bottom", label="GPLv3 Quark-Engine\nhttps://github.com/quark-engine/quark-engine", shape="plaintext",
             fontname="Courier New")

    with dot.subgraph(name="cluster_permission") as permission_subgraph:
        permission_subgraph.attr(style="rounded", penwidth="1", fillcolor="white",
                                 shape="box")
        permission_subgraph.attr(label="Required Permissions", fontname="Courier New Bold")

        # permission node
        permission_subgraph.node("permission", label="\n".join(permission),
                                 fillcolor="white",
                                 fontname="Courier New", shape="none")

    # the last node of each node -> permission
    dot.edge(first_wrappers_list[0], first_native_method, "calls", fontname="Courier New")
    dot.edge(second_wrappers_list[0], second_native_method, "calls", fontname="Courier New")

    dot.edge(first_native_method, "permission", "requests", fontname="Courier New")
    dot.edge(second_native_method, "permission", "requests", fontname="Courier New")

    dot.edge("permission", "bottom", style="invis")

    # show the image
    dot.view()


if __name__ == '__main__':
    # usage
    first_method_list = ["method_1", "method_2", "method_3"]
    second_method_list = ["method_1", "method_2", "method_3"]
    call_graph(first_method_list, second_method_list, crime_description="send location via SMS",
               mutual_parent_function="sendMessage")
