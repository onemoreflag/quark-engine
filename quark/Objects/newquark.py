from quark.Objects.apkinfo import Apkinfo
from prettytable import PrettyTable
import copy

MAX_SEARCH_LAYER = 3


class NewQuark:

    def __init__(self, apk):
        self.apkinfo = Apkinfo(apk)

        self.wrapper_1 = []
        self.wrapper_2 = []

        self.mutual_parent_function_list = []

        self.level_1_result = []
        self.level_2_result = []
        self.level_3_result = []
        self.level_4_result = []
        self.level_5_result = []

        # Json report
        self.json_report = []

        # Pretty Table Output
        self.tb = PrettyTable()
        self.tb.field_names = ["Rule", "Confidence", "Score", "Weight"]
        self.tb.align = "l"

        # Sum of the each weight
        self.weight_sum = 0
        # Sum of the each rule
        self.score_sum = 0

    def find_intersection(self, first_method_analysis_list, second_method_analysis_list, depth=1):

        if first_method_analysis_list and second_method_analysis_list:

            # find ∩
            result = set(first_method_analysis_list).intersection(second_method_analysis_list)

            if result:
                return result
            else:
                # Not found same method usage, try to find the next layer.
                depth += 1
                if depth > MAX_SEARCH_LAYER:
                    return None

                # Append first layer into next layer.
                next_list1 = copy.copy(first_method_analysis_list)
                next_list2 = copy.copy(second_method_analysis_list)

                # Extend the upper function into next layer.
                for item in first_method_analysis_list:
                    if self.apkinfo.upperfunc(item.class_name, item.name) is not None:
                        next_list1.extend(
                            self.apkinfo.upperfunc(
                                item.class_name, item.name,
                            ),
                        )
                for item in second_method_analysis_list:
                    if self.apkinfo.upperfunc(item.class_name, item.name) is not None:
                        next_list2.extend(
                            self.apkinfo.upperfunc(
                                item.class_name, item.name,
                            ),
                        )

                return self.find_intersection(next_list1, next_list2, depth)
        else:
            raise ValueError("List is Null")

    def find_previous_method(self, base_method, parent_function, wrapper, visited_methods=None):

        if visited_methods is None:
            visited_methods = set()

        method_set = self.apkinfo.upperfunc(base_method.class_name, base_method.name)
        visited_methods.add(base_method)

        if method_set is not None:

            if parent_function in method_set:
                wrapper.append(base_method)
            else:
                for item in method_set:
                    # prevent to test the tested methods.
                    if item in visited_methods:
                        continue
                    self.find_previous_method(
                        item, parent_function, wrapper, visited_methods,
                    )

    def run(self, rule_obj):
        """
        Run the five levels check to get the y_score.
        """

        # Level 1

        if self.apkinfo.ret_type == "DEX":
            pass
        elif self.apkinfo.ret_type == "APK":

            if set(rule_obj.x1_permission).issubset(set(self.apkinfo.permissions)):
                rule_obj.check_item[0] = True
            else:
                # Exit if the level 1 stage check fails.
                return

        # Level 2
        api_1_method_name = rule_obj.x2n3n4_comb[0]["method"]
        api_1_class_name = rule_obj.x2n3n4_comb[0]["class"]
        api_2_method_name = rule_obj.x2n3n4_comb[1]["method"]
        api_2_class_name = rule_obj.x2n3n4_comb[1]["class"]

        api_1 = list(self.apkinfo.find_method(api_1_class_name, api_1_method_name))[0]
        api_2 = list(self.apkinfo.find_method(api_2_class_name, api_2_method_name))[0]

        self.level_2_result.clear()

        if api_1 is not None:
            rule_obj.check_item[1] = True
            self.level_2_result.append((api_1_class_name, api_1_method_name))
        elif api_2 is not None:
            rule_obj.x2n3n4_comb[1] = True
            self.level_2_result.append((api_2_class_name, api_2_method_name))
        else:
            return

        # Level 3
        if api_1 is not None and api_2 is not None:
            rule_obj.check_item[2] = True
        else:
            # Exit if the level 3 stage check fails.
            return

        # Level 4

        API_1_xref_from = self.apkinfo.upperfunc(api_1.class_name, api_1.name)
        API_2_xref_from = self.apkinfo.upperfunc(api_2.class_name, api_2.name)

        self.mutual_parent_function_list = self.find_intersection(API_1_xref_from, API_2_xref_from)

        if self.mutual_parent_function_list is not None:

            # Clear the results from the previous rule
            self.level_4_result.clear()
            self.level_5_result.clear()

            for parent_function in self.mutual_parent_function_list:
                self.wrapper_1.clear()
                self.wrapper_2.clear()

                self.find_previous_method(api_1, parent_function, self.wrapper_1)
                self.find_previous_method(api_2, parent_function, self.wrapper_2)

                for item in self.wrapper_2:

                    print(item.class_name)
                    print(item.name)
                    print(item.access)
                    print(item.descriptor)
                    print("####")