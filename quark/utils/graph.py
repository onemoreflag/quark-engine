from graphviz import Digraph


def call_graph(
    first_wrappers_list,
    second_wrappers_list,
    mutual_parent_function=None,
    crime_description=None,
    permission=None,
    register_object=None,
    filename="quark_call_graph",
    first_natvie_call=None,
    second_native_call=None,
):
    """
    Generating a call graph based on two native Android APIs.

    :param first_wrappers_list: a list contains the wrapped functions that based on the first Android API
    :param second_wrappers_list: a list contains the wrapped functions that based on the second Android API
    :param mutual_parent_function: the mutual parent function from given two Android APIs
    :param crime_description: a string about the crime description
    :param permission: a list contains the requested permission by this behavior
    :param register_object: a string contains the contents, which is the evidence of handling the same register
    :param filename: output filename for call graph
    :param first_natvie_call: the first call Android API
    :param second_native_call: the second call Android API
    :return: None
    """
    mutual_method_name = None
    mutual_class_name = None

    # Initialize the Digraph object
    dot = Digraph(
        filename=filename,
        node_attr={"fontname": "Courier New Bold"},
        comment="Quark-Engine Call Graph Result",
        format="svg",
        graph_attr={
            "label": f"Potential Malicious Activity: {crime_description}",
            "labelloc": "top",
            "center": "true",
        },
    )
    dot.attr(compound="true")

    with dot.subgraph(name="cluster_mutual") as mutual_parent_function_description:
        mutual_parent_function_description.attr(
            style="rounded",
            penwidth="1",
            fillcolor="white",
            fontname="Courier New",
            shape="box",
        )
        mutual_parent_function_description.attr(
            label="Mutual Parent Function", fontname="Courier New Bold"
        )

        # mutual parent function node
        mutual_class_name, mutual_method_name = (str(x) for x in mutual_parent_function)
        mutual_parent_function_description.node(
            mutual_method_name,
            label=f"Class: {mutual_class_name.replace(';', '')[1:]}\nMethod: {mutual_method_name}",
            shape="none",
            fontcolor="blue",
            fontname="Courier New",
        )

    with dot.subgraph(name="cluster_0") as wrapper:
        wrapper.attr(label="Wrapped Functions", fontname="Courier New Bold")
        wrapper.attr(style="rounded", penwidth="1", fillcolor="red", shape="box")
        # Build the first call nodes
        for wp_func in first_wrappers_list:
            wp_cls_name, wp_md_name = (str(x) for x in wp_func)

            wrapper.node(
                wp_cls_name + wp_md_name,
                label=f"Class: {wp_cls_name.replace(';', '')[1:]}\nMethod: {wp_md_name}",
                style="rounded",
                fontcolor="blue",
                penwidth="1",
                fillcolor="white",
                fontname="Courier New",
                shape="none",
            )

        # wrapper -> wrapper
        for i in range(len(first_wrappers_list) - 1, 0, -1):
            wp_cls_name_1, wp_md_name_1 = (str(x) for x in first_wrappers_list[i])
            wp_cls_name_2, wp_md_name_2 = (str(x) for x in first_wrappers_list[i - 1])
            wrapper.edge(
                wp_cls_name_1 + wp_md_name_1,
                wp_cls_name_2 + wp_md_name_2,
                "calls",
                fontname="Courier New",
            )

        for wp_func in second_wrappers_list:
            wp_cls_name, wp_md_name = (str(x) for x in wp_func)
            wp_cls_name.replace(";", "")
            wrapper.node(
                wp_cls_name + wp_md_name,
                label=f"Class: {wp_cls_name.replace(';', '')[1:]}\nMethod: {wp_md_name}",
                style="rounded",
                fontcolor="blue",
                penwidth="1",
                fillcolor="white",
                fontname="Courier New",
                shape="none",
            )

        # wrapper -> wrapper
        for i in range(len(second_wrappers_list) - 1, 0, -1):
            wp_cls_name_1, wp_md_name_1 = (str(x) for x in second_wrappers_list[i])
            wp_cls_name_2, wp_md_name_2 = (str(x) for x in second_wrappers_list[i - 1])
            wrapper.edge(
                wp_cls_name_1 + wp_md_name_1,
                wp_cls_name_2 + wp_md_name_2,
                "calls",
                fontname="Courier New",
            )

    with dot.subgraph(name="cluster_1") as native_call_subgraph:
        native_call_subgraph.attr(
            style="rounded",
            penwidth="1",
            fillcolor="white",
            fontname="Courier New",
            shape="box",
        )
        native_call_subgraph.attr(label="Native API Calls", fontname="Courier New Bold")
        # Native API Calls
        first_native_api_class, first_native_method = first_natvie_call
        second_native_api_class, second_native_method = second_native_call
        native_call_subgraph.node(
            first_native_method,
            label=f"Class: {first_native_api_class}\nMethod: {first_native_method}",
            fontcolor="blue",
            shape="none",
            fontname="Courier New",
        )
        native_call_subgraph.node(
            second_native_method,
            label=f"Class: {second_native_api_class}\nMethod: {second_native_method}",
            fontcolor="blue",
            shape="none",
            fontname="Courier New",
        )

    # mutual parent function -> the first node of each node
    first_wp_cls_name_1, first_wp_md_name_1 = (str(x) for x in first_wrappers_list[-1])
    first_wp_cls_name_2, first_wp_md_name_2 = (str(x) for x in second_wrappers_list[-1])

    dot.edge(
        mutual_method_name,
        first_wp_cls_name_1 + first_wp_md_name_1,
        "First Call",
        fontname="Courier New",
    )
    dot.edge(
        mutual_method_name,
        first_wp_cls_name_2 + first_wp_md_name_2,
        "Second Call",
        fontname="Courier New",
    )

    dot.node(
        "bottom",
        label="GPLv3 Quark-Engine\nhttps://github.com/quark-engine/quark-engine",
        shape="plaintext",
        fontname="Courier New",
    )

    with dot.subgraph(name="cluster_permission") as permission_subgraph:
        permission_subgraph.attr(
            style="rounded", penwidth="1", fillcolor="white", shape="box"
        )
        permission_subgraph.attr(
            label="Required Permissions", fontname="Courier New Bold"
        )

        # permission node
        permission_subgraph.node(
            "permission",
            label="\n".join(permission),
            fillcolor="white",
            fontname="Courier New",
            shape="none",
        )

    # the last node of each node -> permission
    last_wp_cls_name_1, last_wp_md_name_1 = (str(x) for x in first_wrappers_list[0])
    last_wp_cls_name_2, last_wp_md_name_2 = (str(x) for x in second_wrappers_list[0])
    dot.edge(
        last_wp_cls_name_1 + last_wp_md_name_1,
        first_native_method,
        "calls",
        fontname="Courier New",
    )
    dot.edge(
        last_wp_cls_name_2 + last_wp_md_name_2,
        second_native_method,
        "calls",
        fontname="Courier New",
    )

    dot.edge(
        first_native_method,
        "permission",
        "requests",
        fontname="Courier New",
        lhead="cluster_permission",
    )
    dot.edge(
        second_native_method,
        "permission",
        "requests",
        fontname="Courier New",
        lhead="cluster_permission",
    )

    dot.edge("permission", "bottom", style="invis")

    # show the image
    dot.render()


if __name__ == "__main__":
    # usage
    first_method_list = ["method_1", "method_2", "method_3"]
    second_method_list = ["method_1", "method_2", "method_3"]
    call_graph(
        first_method_list,
        second_method_list,
        crime_description="send location via SMS",
        mutual_parent_function="sendMessage",
    )
