from graphviz import Digraph


def wrapper_lookup(wrapper, top_method, native_api):
    next_level = []

    for _, meth, _ in top_method.get_xref_to():
        if meth == native_api:
            wrapper.append(top_method)
            return
        elif meth.is_android_api():
            continue
        else:
            next_level.append(meth)

    for next_level_method in next_level:
        wrapper_lookup(wrapper, next_level_method, native_api)


def call_graph(
        native_api_1,
        native_api_2,
        call_graph_analysis,
        crime_description=None,
        apkinfo=None,
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

    # print(native_api_1)
    # print(native_api_2)
    # print(call_graph_analysis)
    # print(crime_description)
    # print(apkinfo)

    parent_function = call_graph_analysis["parent"]
    first_call = call_graph_analysis["first_call"]
    second_call = call_graph_analysis["second_call"]

    if str(second_call.class_name) == "Lahmyth/mine/king/ahmyth/LocManager;" and second_call.name == "<init>":
        second_call = list(apkinfo.analysis.find_methods("Lahmyth/mine/king/ahmyth/LocManager;", "<init>",
                                                         descriptor="\(Landroid/content/Context;\)V"))[0]

    if str(first_call.class_name) == "Lahmyth/mine/king/ahmyth/LocManager;" and first_call.name == "<init>":
        first_call = list(apkinfo.analysis.find_methods("Lahmyth/mine/king/ahmyth/LocManager;", "<init>",
                                                        descriptor="\(Landroid/content/Context;\)V"))[0]

    first_wrapper = []
    second_wrapper = []

    # 有包裝函數
    if first_call != native_api_1:
        # print("第一個呼叫的有包裝函數")
        wrapper_lookup(first_wrapper, first_call, native_api_1)
    if second_call != native_api_2:
        # print("第二個呼叫的有包裝函數")
        wrapper_lookup(second_wrapper, second_call, native_api_2)

    # Initialize the Digraph object
    dot = Digraph(
        filename=f"{parent_function.name}_{first_call.name}_{second_call.name}",
        node_attr={"fontname": "Courier New Bold"},
        comment="Quark-Engine Call Graph Result",
        format="png",
        graph_attr={
            "label": f"Potential Malicious Activity: {crime_description}",
            "labelloc": "top",
            "center": "true",
        },
    )
    dot.attr(compound="true")

    # 母函數

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
        p, r = str(parent_function.descriptor).split(")")
        mutual_parent_function_description.node(
            f"{parent_function.full_name}",
            label=f"Access: {parent_function.access}\nClass: {parent_function.class_name}\nMethod: {parent_function.name}\n Parameter: {p})\n Return: {r}",
            shape="none",
            fontcolor="blue",
            fontname="Courier New",
        )

    # 包裝函數開始

    with dot.subgraph(name="cluster_0") as wrapper:
        wrapper.attr(label="Wrapped Functions", fontname="Courier New Bold")
        wrapper.attr(style="rounded", penwidth="1", fillcolor="red", shape="box")
        # Build the first call nodes

        # 有包裝函數
        if first_call != native_api_1:
            # print("有包裝函數")

            for wp_func in first_wrapper:
                p, r = str(wp_func.descriptor).split(")")

                wrapper.node(
                    f"{wp_func.full_name}",
                    label=f"Access: {wp_func.access}\nClass: {wp_func.class_name}\nMethod: {wp_func.name}\n Parameter: {p})\n Return: {r}",
                    style="rounded",
                    fontcolor="blue",
                    penwidth="1",
                    fillcolor="white",
                    fontname="Courier New",
                    shape="none",
                )

            # wrapper -> wrapper
            for i in range(len(first_wrapper) - 1, 0, -1):
                wrapper.edge(
                    f"{first_wrapper[i].full_name}",
                    f"{first_wrapper[i - 1].full_name}",
                    "calls",
                    fontname="Courier New",
                )

        if second_call != native_api_2:

            for wp_func in second_wrapper:
                p, r = str(wp_func.descriptor).split(")")
                wrapper.node(
                    f"{wp_func.full_name}",
                    label=f"Access: {wp_func.access}\nClass: {wp_func.class_name}\nMethod: {wp_func.name}\n Parameter: {p})\n Return: {r}",
                    style="rounded",
                    fontcolor="blue",
                    penwidth="1",
                    fillcolor="white",
                    fontname="Courier New",
                    shape="none",
                )

            # wrapper -> wrapper
            for i in range(len(second_wrapper) - 1, 0, -1):
                wrapper.edge(
                    f"{second_wrapper[i].full_name}",
                    f"{second_wrapper[i - 1].full_name}",
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

        native_call_subgraph.node(
            f"{native_api_1.full_name}",
            label=f"Class: {native_api_1.class_name}\nMethod: {native_api_1.name}",
            fontcolor="blue",
            shape="none",
            fontname="Courier New",
        )
        native_call_subgraph.node(
            f"{native_api_2.full_name}",
            label=f"Class: {native_api_2.class_name}\nMethod: {native_api_2.name}",
            fontcolor="blue",
            shape="none",
            fontname="Courier New",
        )

    # mutual parent function -> the first node of each node

    # 有包裝函數
    if first_call != native_api_1:
        # print("有包裝函數")

        dot.edge(
            f"{parent_function.full_name}",
            f"{first_wrapper[-1].full_name}",
            "First Call",
            fontname="Courier New",
        )

        dot.edge(
            f"{first_wrapper[0].full_name}",
            f"{native_api_1.full_name}",
            "calls",
            fontname="Courier New",
        )
    else:
        dot.edge(
            f"{parent_function.full_name}",
            f"{native_api_1.full_name}",
            "First Call",
            fontname="Courier New",
        )

    if second_call != native_api_2:
        # print("有包裝函數，有bug")
        # print(len(second_wrapper))
        dot.edge(
            f"{parent_function.full_name}",

            f"{second_wrapper[-1].full_name}",
            "Second Call",
            fontname="Courier New",
        )

        dot.edge(
            f"{second_wrapper[0].full_name}",
            f"{native_api_2.full_name}",
            "calls",
            fontname="Courier New",
        )
    else:
        # 沒有 wrapper function
        dot.edge(
            f"{parent_function.full_name}",
            f"{native_api_2.full_name}",
            "Second Call",
            fontname="Courier New",
        )

    dot.render()
