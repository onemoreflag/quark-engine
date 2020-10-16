# This file is part of Quark Engine - https://quark-engine.rtfd.io
# See GPLv3 for copying permission.
import hashlib
import itertools
import os

from androguard.misc import AnalyzeAPK, AnalyzeDex
from androguard.core import androconf

from quark.Objects.bytecodeobject import BytecodeObject
from quark.utils import tools


class Apkinfo:
    """Information about apk based on androguard analysis"""

    def __init__(self, filepath):
        """Information about apk based on androguard analysis"""
        # return the APK, list of DalvikVMFormat, and Analysis objects

        self.ret_type = androconf.is_android(filepath)

        if self.ret_type == "APK":
            self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(filepath)
        elif self.ret_type == "DEX":
            _, _, self.analysis = AnalyzeDex(filepath)

        self.apk_filename = os.path.basename(filepath)
        self.filepath = filepath

    def __repr__(self):
        return f"<Apkinfo-APK:{self.apk_filename}>"

    @property
    def filename(self):
        """
        Return the filename of apk.

        :return: a string of apk filename
        """
        return os.path.basename(self.filepath)

    @property
    def filesize(self):
        """
        Return the file size of apk file by bytes.

        :return: a number of size bytes
        """
        return os.path.getsize(self.filepath)

    @property
    def md5(self):
        """
        Return the md5 checksum of the apk file.

        :return: a string of md5 checksum of the apk file
        """
        md5 = hashlib.md5()
        with open(self.filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    @property
    def permissions(self):
        """
        Return all permissions from given APK.

        :return: a list of all permissions
        """
        if self.ret_type == "APK":
            return self.apk.get_permissions()
        elif self.ret_type == "DEX":
            return []

    def find_method(self, class_name=".*", method_name=".*", access_flag=None, descriptor=None):
        """
        Find method from given class_name and method_name,
        default is find all method.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :return: a generator of MethodClassAnalysis
        """

        regex_method_name = f"^{method_name}$"

        # precise find method
        if access_flag and descriptor:
            result = self.analysis.find_methods(classname=class_name,
                                                methodname=regex_method_name,
                                                accessflags=access_flag,
                                                descriptor=descriptor,
                                                )
        else:
            result = self.analysis.find_methods(class_name, regex_method_name)
        result, result_copy = itertools.tee(result)

        if list(result_copy):
            return result

        return None

    def upperfunc(self, class_name, method_name):
        """
        Return the upper level method from given class name and
        method name.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :return: a list of all upper functions
        """

        upperfunc_result = []
        method_set = self.find_method(class_name, method_name)

        if method_set is not None:
            for method in method_set:
                for _, call, _ in method.get_xref_from():
                    # Get class name and method name:
                    # call.class_name, call.name
                    upperfunc_result.append((call.class_name, call.name))

            return tools.remove_dup_list(upperfunc_result)

        return None

    def get_method_bytecode(self, class_name, method_name):
        """
        Return the corresponding bytecode according to the
        given class name and method name.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :return: a generator of all bytecode instructions
        """

        result = self.analysis.find_methods(class_name, method_name)

        result, result_copy = itertools.tee(result)

        if list(result_copy):
            for method in result:
                try:
                    for _, ins in method.get_method().get_instructions_idx():
                        bytecode_obj = None
                        reg_list = []

                        # count the number of the registers.
                        length_operands = len(ins.get_operands())
                        if length_operands == 0:
                            # No register, no parameter
                            bytecode_obj = BytecodeObject(
                                ins.get_name(), None, None,
                            )
                        elif length_operands == 1:
                            # Only one register

                            reg_list.append(
                                f"v{ins.get_operands()[length_operands - 1][1]}",
                            )
                            bytecode_obj = BytecodeObject(
                                ins.get_name(), reg_list, None,
                            )
                        elif length_operands >= 2:
                            # the last one is parameter, the other are registers.

                            parameter = ins.get_operands()[length_operands - 1]
                            for i in range(0, length_operands - 1):
                                reg_list.append(
                                    "v" + str(ins.get_operands()[i][1]),
                                )
                            if len(parameter) == 3:
                                # method or value
                                parameter = parameter[2]
                            else:
                                # Operand.OFFSET
                                parameter = parameter[1]

                            bytecode_obj = BytecodeObject(
                                ins.get_name(), reg_list, parameter,
                            )

                        yield bytecode_obj
                except AttributeError as error:
                    # TODO Log the rule here
                    continue
