from prettytable import PrettyTable
from quark.utils.colors import green, red


def big_call_graph(default_dict_call_graph):
    # Pretty Table Output
    tb = PrettyTable()
    tb.field_names = []
    tb.align = "l"

    for key, value in dict(default_dict_call_graph).items():

        # Pretty Table Output
        tb = PrettyTable()
        tb.field_names = ["Parent Function", green(key)]
        tb.align = "l"
        count = 1
        for item in value:
            if item:
                # print(item)
                if count == 1:
                    tb.add_row(["Crime Description",red(str(count) + ". " + item)])
                else:
                    tb.add_row(["", red(str(count) + ". " + item)])

                count += 1

        print("\n\n\n")
        print(tb)
        print("\n\n\n")
