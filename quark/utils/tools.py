import copy


def remove_dup_list(element):
    """
    Remove the duplicate elements in  given list.
    """
    return list(set(element))


def contains(subset_to_check, target_list, mutal_parent_function, record_bridge):
    """
    Check the sequence pattern within two list.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["put", "getCellLocation", "query", "sendTextMessage"]
    then it will return true.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["sendTextMessage", "put", "getCellLocation", "query"]
    then it will return False.
    """
    target_copy = copy.copy(target_list)
    for first in subset_to_check["first_m_call"]:
        for second in subset_to_check["second_m_call"]:
            method_under_parent = [first, second]

            # Delete elements that do not exist in the subset_to_check list
            for item in target_copy:
                if item not in method_under_parent:
                    target_copy.remove(item)

            for i in range(len(target_copy) - len(method_under_parent) + 1):
                for j in range(len(method_under_parent)):
                    if target_copy[i + j] != method_under_parent[j]:
                        break
                else:
                    # build the bridge
                    bg = {"parent": mutal_parent_function, "first_call": first, "second_call": second}
                    record_bridge.append(bg)

                    return True
            return False
