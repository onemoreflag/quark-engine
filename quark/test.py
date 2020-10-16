from androguard.misc import AnalyzeAPK
import itertools
import copy

a, d, dx = AnalyzeAPK("14d9f1a92dd984d6040cc41ed06e273e.apk")

some1 = dx.find_methods("Landroid/telephony/TelephonyManager", "getCellLocation")

some2 = dx.find_methods("Landroid/telephony/SmsManager", "sendTextMessage")
get_location = None
send_sms = None
for _, item, _ in list(some1)[0].get_xref_from():
    get_location = item

for _, item, _ in list(some2)[0].get_xref_from():
    send_sms = item

final_a = None
final_b = None

acw = set()

for _, item, _ in get_location.get_xref_from():

    # print(item)
    if str(item.name) == "sendMessage":
        acw.add(item)
for _, item, _ in send_sms.get_xref_from():

    # print(item)
    if str(item.name) == "sendMessage":
        acw.add(item)

some = list(acw)

print(some[0])

a = copy.copy(some[0])
c = {a:"3"}