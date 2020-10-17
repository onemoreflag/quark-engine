# This file is part of Quark Engine - https://quark-engine.rtfd.io
# See GPLv3 for copying permission.

import copy
import operator

from prettytable import PrettyTable

from quark.Objects.apkinfo import Apkinfo
from quark.analyzer.android.pyeval import PyEval
from quark.utils import tools
from quark.utils.colors import (
    red,
    bold,
    yellow,
    green,
)
from quark.utils.weight import Weight

MAX_SEARCH_LAYER = 3
CHECK_LIST = "".join(["\t[" + "\u2713" + "]"])


class NewQuark:
    def __init__(self, apk):
        self.apkinfo = Apkinfo(apk)

        self.wrapper_1 = []
        self.wrapper_2 = []

        self.seqence_bridge = []
        self.register_bridge = []

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

    def clean_result(self):

        self.level_1_result.clear()
        self.level_2_result.clear()
        self.level_3_result.clear()
        self.level_4_result.clear()
        self.level_5_result.clear()

    def find_intersection(
            self, first_method_analysis_list, second_method_analysis_list, depth=1
    ):

        if first_method_analysis_list and second_method_analysis_list:

            # find ∩
            result = set(first_method_analysis_list).intersection(
                second_method_analysis_list
            )

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
                                item.class_name,
                                item.name,
                            ),
                        )
                for item in second_method_analysis_list:
                    if self.apkinfo.upperfunc(item.class_name, item.name) is not None:
                        next_list2.extend(
                            self.apkinfo.upperfunc(
                                item.class_name,
                                item.name,
                            ),
                        )

                return self.find_intersection(next_list1, next_list2, depth)
        else:
            raise ValueError("List is Null")

    def find_previous_method(
            self, base_method, parent_function, wrapper, visited_methods=None
    ):

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
                        item,
                        parent_function,
                        wrapper,
                        visited_methods,
                    )

    def check_sequence(self, mutual_parent_function, first_call_meth_list, second_call_meth_list):

        method_set = self.apkinfo.find_method(
            mutual_parent_function.class_name,
            mutual_parent_function.name,
        )
        seq_table = []

        if method_set is not None:

            for method in method_set:
                for _, call, number in method.get_xref_to():

                    if call in first_call_meth_list or call in second_call_meth_list:
                        seq_table.append((call, number))

            # sorting based on the value of the number
            if len(seq_table) < 2:
                # Not Found sequence in same_method
                return False
            seq_table.sort(key=operator.itemgetter(1))
            # seq_table would look like: [(getLocation, 1256), (sendSms, 1566), (sendSms, 2398)]

            method_list = [x[0] for x in seq_table]
            check_sequence_method = {"first_m_call": first_call_meth_list, "second_m_call": second_call_meth_list}

            return tools.contains(check_sequence_method, method_list, mutual_parent_function, self.seqence_bridge)
        else:
            return False

    def check_parameter(self, mutual_parent_function, first_call, second_call):

        pyeval = PyEval()
        # Check if there is an operation of the same register
        state = False

        for bytecode_obj in self.apkinfo.get_method_bytecode(
                mutual_parent_function.class_name, mutual_parent_function.name,
        ):
            # ['new-instance', 'v4', Lcom/google/progress/SMSHelper;]
            instruction = [bytecode_obj.mnemonic]
            if bytecode_obj.registers is not None:
                instruction.extend(bytecode_obj.registers)
            if bytecode_obj.parameter is not None:
                instruction.append(bytecode_obj.parameter)

            # for the case of MUTF8String
            instruction = [str(x) for x in instruction]

            if instruction[0] in pyeval.eval.keys():
                pyeval.eval[instruction[0]](instruction)

        for table in pyeval.show_table():
            for val_obj in table:
                matchers = [f"{first_call.class_name}->{first_call.name}{first_call.descriptor}",
                            f"{second_call.class_name}->{second_call.name}{second_call.descriptor}"]
                matching = [
                    s for s in val_obj.called_by_func if all(xs in s for xs in matchers)
                ]
                if matching:
                    state = True
                    break
        return state

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

        api_1 = self.apkinfo.find_method(api_1_class_name, api_1_method_name)
        api_2 = self.apkinfo.find_method(api_2_class_name, api_2_method_name)

        if api_1 is not None:
            rule_obj.check_item[1] = True

            self.level_2_result.append(list(self.apkinfo.find_method(api_1_class_name, api_1_method_name))[0])
        if api_2 is not None:
            rule_obj.x2n3n4_comb[1] = True

            self.level_2_result.append(list(self.apkinfo.find_method(api_2_class_name, api_2_method_name))[0])

        # Level 3
        if api_1 is not None and api_2 is not None:
            rule_obj.check_item[2] = True
            api_1 = list(self.apkinfo.find_method(api_1_class_name, api_1_method_name))[0]
            api_2 = list(self.apkinfo.find_method(api_2_class_name, api_2_method_name))[0]
            self.level_3_result.append(api_1)
            self.level_3_result.append(api_2)
        else:
            # Exit if the level 3 stage check fails.
            return

        # Level 4

        API_1_xref_from = self.apkinfo.upperfunc(api_1.class_name, api_1.name)
        API_2_xref_from = self.apkinfo.upperfunc(api_2.class_name, api_2.name)

        self.mutual_parent_function_list = self.find_intersection(
            API_1_xref_from, API_2_xref_from
        )

        if self.mutual_parent_function_list is not None:

            for parent_function in self.mutual_parent_function_list:
                self.wrapper_1.clear()
                self.wrapper_2.clear()

                self.find_previous_method(api_1, parent_function, self.wrapper_1)
                self.find_previous_method(api_2, parent_function, self.wrapper_2)

                meth_1_under_parent_func_list = copy.copy(self.wrapper_1)
                meth_2_under_parent_func_list = copy.copy(self.wrapper_2)

                if self.check_sequence(parent_function, meth_1_under_parent_func_list, meth_2_under_parent_func_list):
                    rule_obj.check_item[3] = True
                    self.level_4_result.append(parent_function)

                    # Level 5
                    for bg in self.seqence_bridge:

                        if self.check_parameter(bg["parent"], bg["first_call"], bg["second_call"]):
                            rule_obj.check_item[4] = True
                            self.register_bridge.append(bg)
                            self.level_5_result.append(bg["parent"])


        else:
            # Exit if the level 4 stage check fails.
            return

    def get_json_report(self):
        """
        Get quark report including summary and detail with json format.

        :return: json report
        """

        w = Weight(self.score_sum, self.weight_sum)
        warning = w.calculate()

        # Filter out color code in threat level
        for level in ["Low Risk", "Moderate Risk", "High Risk"]:
            if level in warning:
                warning = level

        json_report = {
            "md5": self.apkinfo.md5,
            "apk_filename": self.apkinfo.filename,
            "size_bytes": self.apkinfo.filesize,
            "threat_level": warning,
            "total_score": self.score_sum,
            "crimes": self.json_report,
        }

        return json_report

    def generate_json_report(self, rule_obj):
        """
        Show the json report.

        :param rule_obj: the instance of the RuleObject
        :return: None
        """
        # Count the confidence
        confidence = str(rule_obj.check_item.count(True) * 20) + "%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.yscore

        # Assign level 1 examine result
        permissions = []
        if rule_obj.check_item[0]:
            permissions = rule_obj.x1_permission

        # Assign level 2 examine result
        api = []
        if rule_obj.check_item[1]:
            for class_name, method_name in self.level_2_reuslt:
                api.append({
                    "class": class_name,
                    "method": method_name,
                })

        # Assign level 3 examine result
        combination = []
        if rule_obj.check_item[2]:
            combination = rule_obj.x2n3n4_comb

        # Assign level 4 - 5 examine result if exist
        sequnce_show_up = []
        same_operation_show_up = []

        # Check examination has passed level 4
        if self.level_4_result and rule_obj.check_item[3]:
            for same_sequence_cls, same_sequence_md in self.level_4_result:
                sequnce_show_up.append({
                    "class": repr(same_sequence_cls),
                    "method": repr(same_sequence_md),
                })

            # Check examination has passed level 5
            if self.level_5_result and rule_obj.check_item[4]:
                for same_operation_cls, same_operation_md in self.level_5_result:
                    same_operation_show_up.append({
                        "class": repr(same_operation_cls),
                        "method": repr(same_operation_md),
                    })

        crime = {
            "crime": rule_obj.crime,
            "score": score,
            "weight": weight,
            "confidence": confidence,
            "permissions": permissions,
            "native_api": api,
            "combination": combination,
            "sequence": sequnce_show_up,
            "register": same_operation_show_up,
        }
        self.json_report.append(crime)

        # add the weight
        self.weight_sum += weight
        # add the score
        self.score_sum += score

    def show_summary_report(self, rule_obj):
        """
        Show the summary report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        # Count the confidence
        confidence = str(rule_obj.check_item.count(True) * 20) + "%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.yscore

        self.tb.add_row([
            green(rule_obj.crime), yellow(
                confidence,
            ), score, red(weight),
        ])

        # add the weight
        self.weight_sum += weight
        # add the score
        self.score_sum += score

    def show_detail_report(self, rule_obj):
        """
        Show the detail report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """

        # Count the confidence
        print("")
        print(f"Confidence: {rule_obj.check_item.count(True) * 20}%")
        print("")

        if rule_obj.check_item[0]:

            print(red(CHECK_LIST), end="")
            print(green(bold("1.Permission Request")), end="")
            print("")

            for permission in rule_obj.x1_permission:
                print(f"\t\t {permission}")
        if rule_obj.check_item[1]:
            print(red(CHECK_LIST), end="")
            print(green(bold("2.Native API Usage")), end="")
            print("")

            for result in self.level_2_result:
                print(f"\t\t {result.class_name}{result.name}")
        if rule_obj.check_item[2]:
            print(red(CHECK_LIST), end="")
            print(green(bold("3.Native API Combination")), end="")

            print("")
            for result in self.level_3_result:
                print(
                    f"\t\t {result.class_name}{result.name}"
                )

        if rule_obj.check_item[3]:

            print(red(CHECK_LIST), end="")
            print(green(bold("4.Native API Sequence")), end="")

            print("")
            print(f"\t\t Sequence show up in:")
            for seq_method in self.level_4_result:
                print(f"\t\t {repr(seq_method.full_name)}")
        if rule_obj.check_item[4]:

            print(red(CHECK_LIST), end="")
            print(green(bold("5.Native API Use Same Parameter")), end="")
            print("")
            for seq_operation in self.level_5_result:
                print(f"\t\t {seq_operation.full_name}")

        self.clean_result()


if __name__ == "__main__":
    pass
