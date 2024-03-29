import base64

REGISTER_MAX = 0xFFFFFFFF


def rol(number):
    if (number * 2) > 0xFFFFFFFF:
        number = ((number * 2) & 0xFFFFFFFF) + 1
        return number

    else:
        return number * 2


def ror(number):
    left = number % 2
    if left:
        number = (number >> 1) + left * (2 ** 31)
    else:
        number = (number >> 1)
    return number


def crackme3():
    import binascii
    # data = '3131313131313131313131313131'
    # serial = ''
    # b = 0x41
    # for i in range(0, len(data), 2):
    #     hexdata = eval('0x' + data[i:i+2])
    #     hexdata = hexdata ^ b
    #     b += 1
    #     serial += str(hex(hexdata)[2:])
    # print(serial)

    # 输入长度需要14位，否则需补齐，懒得写了
    name = input('<<').encode('UTF-8').hex()
    serial = 0x00
    final_name = ''
    b = 0x4E
    for i in range(len(name)-1, 0, -2):
        hexdata = eval('0x' + name[i-1:i+1])
        serial += hexdata
        hexdata = hexdata ^ b
        b -= 1
        final_name = str(hex(hexdata)[2:]) + final_name

    serial ^= 0x12345678
    final_serial = ''
    for i in range(2, len(hex(serial)), 2):
        final_serial = hex(serial)[i:i+2] + final_serial
    final_serial = final_name + final_serial
    print(final_serial)


def crackme6():
    name = 'wa1ex'
    serial = ''
    cl = 0x5
    for i in name:
        temp = chr(ord(i) - cl)
        serial += temp
        cl -= 1
    print(serial)


def crackme8():
    name = 'zhangyufan'
    length = len(name)
    temp = 'AKA-' + str(str(length * 0x17CFB + ord(name[0])).encode())[2:-1]
    print(temp)


def crackme9():
    name = 'wa1ex'
    serial = 'Bon-'
    mutli = 0xffffffff
    limit = mutli + 1
    ebx = 0
    for i in name:
        eax = ord(i)-0x19
        ebx -= eax
    ebx = limit + ebx
    serial = serial + hex(ebx)[2:].upper() + '-'

    eax = (ebx * ebx) & mutli
    ebx = (ebx * eax) & mutli
    serial = serial + hex(ebx)[2:].upper() + '-'

    eax = ebx = ecx = 0x40E0F8
    ecx = (ecx * ebx) & mutli
    ecx -= eax
    serial = serial + hex(ecx)[2:].upper()
    print(serial)


def crackme11():
    name = 'wa1ex'
    serial = name[::-1]
    print(serial)


def crackme12():
    name = 'wa1ex'
    serial = '123456'
    al = 0
    for i in range(len(name)):
        bl = ord(name[i])
        al += bl
    temp1 = (al << 3) ^ 0x515A5
    # 字符串变整数
    # print(serial)
    # eax = 0xA
    # edi = 0
    # for i in range(len(serial)):
    #     bl = ord(serial[i]) - 0x30
    #     edi = eax * edi + bl
    # print(edi)
    # edi ^= 0x87CA
    # ebx = edi
    # eax = temp1 + ebx
    # eax ^= 0x797E7
    eax = 0x797E7
    ebx = eax - temp1
    edi = ebx
    edi ^= 0x87CA
    print(edi)


def crackme13():
    name = 'wa1ex'
    # temp1 = (ord(name[0]) << 3) - ord(name[0])
    # print(hex(temp1))
    # temp2 = (ord(name[1]) << 4)
    # temp1 += temp2
    # print(hex(temp1))
    eax = ord(name[0]) * 0x29
    eax *= 2
    serial = 'CW-' + str(eax) + '-CRACKED'
    print(serial)


def crackme14():
    name = 'wa1ex'
    ecx = 10
    ebx = 0
    serial = ''
    for i in name:
        edx = ((ord(i) % ecx) ^ ebx) + 0x2
        if edx > 0xA:
            edx -= 0xA
        ebx += 1
        edx += 8 * 0xA
        serial += chr(edx)
    print(serial)
    # for i in serial:
    #     edx = ord(i) % ecx


def crackme16():
    serial = '12-456-89'
    total = 0
    for i in range(1000000, 9999999):
        current = i
        while current != 0:
            res = current % 10
            total += res ** 7
            current //= 10

        if total == i:
            print(str(i)[0:2] + '-' + str(i)[2:5] + '-' + str(i)[5:7])
        total = 0
        # 1741725
        # 4210818
        # 9800817
        # 9926315


def crackme17():
    # hardcode
    return


def crackme18():
    name = 'wa1ex'
    local1 = 'BA7069C6'
    local1_after_call = 'A71809C1'
    local2_after_call = '4E301383'
    # 根据盘符和一系列变换得到的local4
    local4 = 0x625FBB16
    eax = 1
    edx = 0
    for i in name:
        eax *= ord(i)
        if eax > 0xFFFFFFFF:
            edx = eax // 0x100000000
        else:
            edx = 0
        eax += edx
        eax &= 0xFFFFFFFF
        print(hex(eax))
    eax = rol(eax)
    eax |= local4
    eax &= 0xFFFFFFF
    key_402073 = '071362de9f8ab45c'
    serial = ''
    while eax != 0:
        ecx = 0x10
        index = eax % ecx
        serial += key_402073[index]
        eax //= 0x4
        print(eax)
    print(serial)


def crackme20():
    raw_name = input("<<")
    name = ''
    cl = 1
    for i in raw_name:
        bl = ord(i)
        bl = cl ^ bl
        name += chr(bl)
        cl += 1
    print(name)

    cl = 0xA
    password = ''
    for i in name:
        bl = ord(i)
        password += chr(cl ^ bl)
        cl += 1
    print(password)


def crackme21():
    raw_name = 'wa1ex'
    password = ''
    a = 0
    for i in raw_name:
        value = ord(i)
        if value == 0x5A:
            value -= 1
        if value == 0x7A:
            value -= 1
        if value == 0x39:
            value -= 1
        eax = 0x61 + a
        bl = value + 1
        bh = eax
        a += 1
        password += chr(bl) + chr(bh)
    print(password)


def crackme22():
    password = '6287-A'


def crackme23():
    raw_name = 'fatestede'
    esi = 0
    bl_list = [0x0c, 0x0a, 0x13, 0x09, 0x0c, 0x0b, 0x0a, 0x08]
    for i in range(3, len(raw_name)):
        dl = ord(raw_name[i])
        bl = bl_list[i-3]
        dl = dl * bl
        esi += dl
    print(esi)


def crackme24():
    password = 'GGGGGGGGGGGGGGGG'


def crackme25():
    username = 'DiKeN' + 'wa1ex'
    checkcode = '3081071428'
    # eax = 0xffffffff
    # for i in username:
    #     eax ^= ord(i)
    edx = 0
    # 算是字符串到int吧
    for i in checkcode:
        edx = 10*edx + ord(i) - 0x30
    print(edx)


def crackme26():
    name = 'wa1ex'
    esi = 0
    for i in name:
        edx = ord(i)
        ebx = edx
        ebx *= edx
        esi += ebx
        ebx = edx
        ebx //= 2
        ebx += 3
        ebx *= edx
        ebx -= edx
        esi += ebx
        esi *= 2
    print(hex(esi)[0:2] + (10-len(hex(esi)))*'0' + hex(esi)[2:])


def crackme29():
    name = 'wa1ex'
    serial = ''
    edi = 0
    for i in name:
        serial += chr(ord(i) - edi)
        edi += 1
    print(serial)


def crackme30():
    name = 'fatestede'
    esi = 0
    for i in range(0, 6):
        eax = ord(name[i])
        esi += 2 * eax
        print(hex(esi))
    serial = esi + len(name) * 2
    print(serial)


def crackme31():
    name = 'walex'
    name = name.upper()
    edi = 0
    for i in name:
        edi += ord(i)
    print(hex(edi))
    serial = edi ^ 0x5678 ^ 0x1234
    print(serial)


def crackme32():
    name = 'wa1ex'
    esi = 0
    for i in name:
        edx = ord(i)
        ebx = edx * edx
        esi += ebx
        ebx = (edx >> 1)
        esi = esi + ebx - edx
    print(esi)


def crackme33():
    name = 'wa1ex'
    esi = 0
    for i in name:
        eax = ord(i)
        ebx = eax
        ebx = (ebx-0x17) * (eax-0x11)
        esi += ebx
    print(esi)


def crackme36():
    name = 'fatestede'
    esi = 0
    for i in name:
        eax = ord(i)
        esi += eax
    serial = 0x499602D2 * esi
    print(str(serial)[0:3] + '-' + str(serial)[4:8] + '-' + str(serial)[9:])


def crackme37():
    name = 'wa1ex'
    serial = name + name + '625g72'
    print(serial)


def crackme38():
    add_num = [0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65]
    # Reverse
    for num in add_num:
        print(chr(num))


def crackme39():
    name = 'fatestede'
    table1 = 'LANNYDIBANDINGINANAKEKHYANGNGENTOT'
    serial = ''
    ebx = 0
    for i in range(0, len(name)):
        ebx += ord(name[i])
        ebx *= 256
        if ebx > 2 ** 32:
            ebx %= 2 ** 32
        edx = ord(table1[i])
        ebx |= edx
        if ebx >> 31:
            edx = 0x100000000 - ebx
            ebx = edx
    ebx ^= 0x12345678
    print(hex(ebx))
    table2 = 'LANNY5646521'
    while ebx:
        edx = ebx % 10
        ebx //= 10
        serial += table2[edx]
    print(serial)


def crackme40():
    name = 'wa1ex'
    serial = ''
    for i in name:
        serial += chr(ord(i) + 5)
    print(serial)


def crackme41():
    name = 'wa1ex'
    for i in range(0, 5):
        if i == 1:
            continue
        serial = ord(name[i])
        serial = serial // 0xA
        if serial >= 0xA:
            serial = serial // 0xA
        print(serial)


def crackme42():
    # 75 52 78
    # 75 83 41
    # serial = '0TbD23456789'
    # print(hex(0x55 * 0x8B * 0xEC))
    # 遍历符合条件的前三个字节
    # result = 0x2A8BF4
    # for i in range(0x21, 0x7E):
    #     for j in range(0x21, 0x7E):
    #         for k in range(0x21, 0x7E):
    #             if (i ^ len(serial) ^ 0x54 ^ 0x1e) * (j ^ len(serial) ^ 0xbf ^ 0x4d) * (k ^ len(serial) ^ 0xa2 ^ 0x47)==result:
    #                 print(chr(i)+chr(j)+chr(k))
    # 算法变形
    # serial1 = ''
    # for i in serial:
    #     serial1 += chr(ord(i) ^ len(serial))
    # serial2 = ''
    # serial2 += chr(ord(serial1[0]) ^ 0x54)
    # serial2 += chr(ord(serial1[1]) ^ 0x4D)
    # serial2 += chr(ord(serial1[2]) ^ 0x47)
    # serial2 = serial2 + serial1[3:]
    # print(serial2)
    #
    # esi = edi = 3
    # # 手动订了一个0x20 D
    # # print(chr(0x20 ^ ord(serial2[0]) ^ len(serial)))
    # # 0TbD23456789
    # while esi < len(serial):
    #     dl = ord(serial2[0])
    #     eax = esi + 1
    #     esi += edi
    #     serial2 = serial2[0:eax-1] + chr(ord(serial2[eax-1]) ^ dl) + serial2[eax:]
    #     dl = ord(serial2[1])
    #     serial2 = serial2[0:eax] + chr(ord(serial2[eax]) ^ dl) + serial2[eax+1:]
    #     dl = ord(serial2[2])
    #     serial2 = serial2[0:eax+1] + chr(ord(serial2[eax+1]) ^ dl) + serial2[eax + 2:]
    # print(hex(ord((serial2[3]))))
    # print(serial2)
    # member_405030 = [0x1e, 0xbf, 0xa2]
    # for i in range(0, len(member_405030)):
    #     member_405030[i] ^= ord(serial2[i])
    # total = 1
    # for i in member_405030:
    #     total *= i
    # print(hex(total))

    serial_len = 9
    result = [0x55, 0x8B, 0xEC, 0x00, 0x77, 0x61, 0x31, 0x65, 0x78]
    result[0] = result[0] ^ 0x1E
    result[1] = result[1] ^ 0xBF
    result[2] = result[2] ^ 0xA2
    print(result[0], result[1], result[2])
    result[3] = result[0] ^ 0x20
    for i in range(4, serial_len):
        if i % 3 == 1:
            result[i] ^= result[1]
        elif i % 3 == 2:
            result[i] ^= result[2]
        else:
            result[i] ^= result[0]
    result[0] = result[0] ^ 0x54
    result[1] = result[1] ^ 0x4D
    result[2] = result[2] ^ 0x47
    for i in range(0, serial_len):
        result[i] ^= serial_len
    for i in result:
        print(hex(i))


def crackme44():
    print((chr(0x74) + chr(0x73) + chr(0x72) + chr(0x68)))
    name = 'wa1ex'
    middle_num = 2003 + len(name)
    serial = "tsrh-" + str(middle_num) + "-"
    final_serial = 'tsrh-2008-'
    unknow1 = 0x68727374 + 0x3220
    serial_len = len(serial)
    for i in name:
        eax = ord(i) + 0xC
        edx = 2 * eax - 0x11 - serial_len
        eax ^= edx
        serial += hex(eax)[2:4]
        serial_len = len(serial)
    print(serial)
    unknow1 ^= 0x403321
    for i in range(0, len(name)):
        if i == 0:
            serial_index = 0xC
            edx = ord(serial[serial_index])
        else:
            edx = 0x0
        eax = ord(name[i]) + 1
        eax ^= edx
        while eax < 0x41:
            eax += 0x8
        while eax > 0x5A:
            eax -= 0x3
        final_serial += chr(eax)
    print(final_serial)


def crackme45():
    name = 'wa1ex'
    result = 1
    for i in name:
        result = (result * ord(i)) & 0xFFFFFFFF
    result &= 0xFFFFFFF
    print(result)


def crackme46():
    serial = '0x01CE8E1A'
    print(eval(serial))


def crackme47():
    serial = 'wa1exzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzC'
    total = 0
    for i in serial:
        total += ord(i)
    print(hex(total))
    print(chr(0x20A9-0x2066))


def crackme48():
    name = 'wa1ex'
    arg1 = 0x4DE1
    serial = ''
    for i in name:
        al = ord(i)
        al ^= (arg1 >> 8)
        serial += hex(al)[2:4].upper()
        al += arg1
        al = (al * 0xCE6D) & 0xFFFF
        al = (al + 0x58BF) & 0xFFFF
        arg1 = al
    print(serial)


def crackme49():
    name = 'wa1ex'
    serial = '0'
    for i in name:
        serial += hex(ord(i))[2:4]
    print(serial)


def crackme50():
    name = 'wwwwwa1ex'
    serial = ''
    for i in name:
        serial += chr(ord(i)-4)
    serial = serial[0:3] + '-' + serial[3] + '-axd' + serial[4:]
    print(serial)


def crackme51():
    name = 'wa1ex'
    ecx = 0
    serial = 0
    eax = 0
    for i in name:
        ecx += 1
        eax = ord(i) ^ ecx
        serial += eax
    eax *= 0x6
    serial <<= 0x7
    eax += serial
    print(hex(eax).upper()[2:])


def crackme52():
    name = 'wa1ex'
    total = 0
    bl = 0
    ebp_014 = 1
    for i in name:
        if bl < ord(i):
            bl = 0x100 + bl - ord(i)
        else:
            bl -= ord(i)
        bl += ebp_014
        total += bl
        ebp_014 += 1
        print(hex(total))
    if total < 0x438D:
        total += 0x45E6
    print(str(total)[0:2] + '-' + str(total)[2:3] + '-' + str(total)[3:])


def crackme53():
    name = 'wa1ex'
    name_new1 = ''
    for i in range(0, 5):
        name_new1 += name[4-i]
    name_new2 = ''
    for i in range(0, 5):
        name_new2 += chr(ord(name_new1[i]) ^ 0x30 ^ 0x20)
    print(name_new2)


def crackme54():
    name = 'w-a1ex'
    ebp = 0
    for i in name:
        ebp += ord(i)
    ebp += 0x6064
    sebp = str(ebp)
    ebp += 0x6064
    temp = name[0:2] + name[-1].upper() + sebp + '-' + str(ebp)
    print(temp)


def crackme55():
    # return zero
    return


def crackme56():
    name = 'wa1ex'
    serial_list = []
    serial = ''
    al = 0x5
    for i in name:
        cl = (ord(i) ^ 0x29) + al
        if (cl > 0x5A) | (cl < 0x41):
            cl = 0x52 + al
            serial_list.append(hex(cl))
        else:
            serial_list.append(hex(cl))
        al -= 1
    al = 0x5
    for i in name:
        cl = (ord(i) ^ 0x27) + al + 0x1
        if (cl > 0x5A) | (cl < 0x41):
            cl = 0x4D + al
            serial_list.append(hex(cl))
        else:
            serial_list.append(hex(cl))
        al -= 1
    for i in serial_list:
        serial += chr(eval(i))
    print(serial)
    cl = 0
    serial1 = ''
    for i in serial:
        dl = ord(i) + 5
        if dl > 0x5A:
            dl -= 0xD
        dl ^= 0xC
        if dl < 0x41:
            dl = 0x4B + cl
        if dl > 0x5A:
            dl = 0x4B - cl
        cl += 1
        serial1 += chr(dl)
    print(serial1)


def crackme58():
    # name = 'wa1ex'
    # str1 = 'crackme'
    # str2 = '657uthutduehdhdhd,ljhgs4sgf4s5s5gs5sg5g45s4g5dgyshste][gf]fg]f]d]'
    # temp = []
    # for i in range(0, len(name)):
    #     edx = ord(str1[i])
    #     ecx = ord(str2[i])
    #     cal = ecx & edx
    #     cal &= ord(str1[i])
    #     cal ^= ord(str2[i])
    #     cal += i
    #     temp.append(hex(cal))
    # temp.append(hex(len(name)))
    # serial = '0x'
    # for i in temp:
    #     serial += i[2:]
    print(0x423820)


def crackme59():
    name = 'ewa1ex'
    dict_alp = {'a': 0x18, 'e': 0xD, 'w': 0x58, 'x': 0xA}
    total = 0x5D
    for i in range(0, 5):
        if dict_alp.get(name[i]):
            value = dict_alp.get(name[i])
        else:
            value = 0x5D
        total += value
        if total >= 0x100:
            total -= 0x100
    print(str(total) + '-' + str(6 * 0x4A7E))


def crackme60():
    import numpy as np
    np.set_printoptions(linewidth=np.inf)
    area = np.zeros((16, 16)).astype(int)
    name = 'wa1ex'
    PointRecord = np.zeros((2, len(name) + 2)).astype(int)
    serial = ''
    dl = 0
    for i in name:
        dl += ord(i)
        if dl >= 0x100:
            dl -= 0x100
    for i in range(0, len(name)):
        al = ord(name[i])
        al ^= dl
        dl -= al
        if dl < 0:
            dl += 0x100
        area[al // 16][al % 16] ^= 0xCC
        PointRecord[0][i+1] = (al // 16)
        PointRecord[1][i+1] = (al % 16)
        if not area[al // 16][al % 16]:
            dl -= 1
            dl -= al
            if dl < 0:
                dl += 0x100
            area[al // 16][al % 16] ^= 0xCC
            PointRecord[0][i] = (al // 16)
            PointRecord[1][i] = (al % 16)
    dl ^= al
    while True:
        al -= dl
        if al < 0:
            al += 0x100
        if area[al // 16][al % 16] != 0xCC:
            break
        dl -= 1
    area[al // 16][al % 16] = 0xDD
    PointRecord[0][len(name) + 1] = (al // 16)
    PointRecord[1][len(name) + 1] = (al % 16)
    al = dl
    while True:
        if (area[al // 16][al % 16] != 0xCC) and (area[al // 16][al % 16] != 0xDD):
            area[al // 16][al % 16] = 0x99
            break
        else:
            al -= 1
    PointRecord[0][0] = (al // 16)
    PointRecord[1][0] = (al % 16)
    for i in range(0, len(name) + 1):
        line_distance = PointRecord[1][i] - PointRecord[1][i+1]
        row_distance = PointRecord[0][i] - PointRecord[0][i+1]
        if line_distance > 0:
            serial += '2' * line_distance
        else:
            serial += '3' * (-line_distance)
        if row_distance > 0:
            serial += '1' * row_distance
        else:
            serial += '0' * (-row_distance)
    print(serial)


def crackme61():
    name = 'wa1ex'
    name = name + (16 - len(name)) * '1'
    ebx = 0
    for i in name:
        eax = ord(i)
        eax += 0xF
        eax ^= 0x20
        ebx += eax
        print(hex(ebx))
    ebx = ebx * 0x7A69
    print(name + hex(ebx)[2:].upper())


def crackme62():
    name = 'wa1ex'
    serial = ' ' + name[1:]
    print(serial)


def crackme63():
    name = 'wa1ex'
    hard_str1 = ';;;;;;;;;;;;;**====,,=,,========*=**=*=**=*=**=*=*=* '
    hard_str2 = ''
    for i in hard_str1:
        hard_str2 += chr(ord(i)+1)
    local4 = len(hard_str2) + 2
    hardcode_name = []
    for i in hard_str2:
        hardcode_name.append(ord(i))
    hardcode_name.append(0)
    for i in name:
        hardcode_name.append(ord(i))
    hardcode_name.append(0)

    for i in range(0, 100):
        ecx = hardcode_name[i]
        if ecx > 0x3C:
            if ecx == 0x3e:
                local4 += 1
            elif ecx == 0x5B:
                ecx = local4
                if hardcode_name[ecx-1]:
                    continue
                else:
                    i += 1
                    while True:
                        if hardcode_name[i] == 0x5D:
                            break
                        else:
                            i += 1
                            continue
            elif ecx == 0x5D:
                ecx = local4
                if hardcode_name[ecx-1]:
                    continue
                else:
                    i -= 1
                    while True:
                        if hardcode_name[i] == 0x5D:
                            break
                        else:
                            i -= 1
                            continue
        elif ecx == 0x3c:
            local4 -= 1
        elif ecx == 0x21:
            break
        elif ecx == 0x2B:
            ecx = local4
            hardcode_name[ecx-1] += 1
        elif ecx == 0x2D:
            ecx = local4
            hardcode_name[ecx-1] -= 1
    edi = 0x19f568
    for i in range(1, 10):
        eax = len(hard_str2) + i
        try:
            eax = hardcode_name[eax-1]
        except IndexError as e:
            continue
        edi += eax
    print(edi)


def crackme66():
    hard_str = 'kXy^rO|*yXo*m\kMuOn*+'
    serial = ''
    for i in hard_str:
        serial += chr(ord(i)-10)
    print(serial)
    # aNoThEr oNe cRaCkEd !


def crackme68():
    hard_str = '203945709398475029384750293875577934765620110289347563929867122287863095762304984875020398746563'
    name = 'wwa1ex'
    serial = ''
    for i in name:
        edx = ord(i) - 0x20
        serial += hard_str[edx]
    print(serial)


def crackme69():
    name = 'wa1ex'
    serial = ''
    for i in name:
        esi = ord(i)
        ecx = 0x6
        eax = esi//ecx
        edx = esi
        edx >>= 0x2
        eax *= edx
        temp = eax

        ecx = 0xA
        edx = esi//ecx
        eax = temp
        result = eax//edx
        serial += str(result)
    print('ADCM4-' + serial + '-YEAH!')


def crackme71():
    name = 'wa1ex1'
    hardcode = '31415926535897932384'
    serial = ''
    eax = 0
    for i in range(0, len(name)):
        al = ord(name[i])
        ebp = ord(hardcode[i])
        edx = al % ebp
        eax = edx * 2
        if eax > 0x7B:
            eax -= 0x1A
        if eax < 0x41:
            edx = 0x82
            edx -= eax
            eax = edx
        if (eax > 0x5B) and (eax < 0x61):
            eax = eax % 10 + 0x30
        serial += chr(eax)
    print(serial)


def crackme72():
    name = 'wwwwwa1ex'
    # 假
    pos_4038FC = len(name)
    serial = ''
    for i in range(0, len(name) + 1):
        ecx = (pos_4038FC * (i+1) + 0x17) ^ 0xF
        eax = ecx
        serial += str(eax)
    print(serial)

    ax = 0x6177 ^ 0xE32F
    ax = (ax * ax) & 0xFFFF
    ax ^= 0xAB6C
    print(hex(ax))


def crackme81():
    eax = 500794
    ecx = 0x78C
    eax //= ecx
    eax *= 0x399
    eax <<= 17
    if eax >= 0x100000000:
        eax %= 0x100000000
    eax >>= 9
    ecx = 0xC
    eax //= ecx
    print(eax)


def crackme82():
    name = 'wa1ex'
    ecx = ((ord(name.upper()[0]) * len(name)) << 0xC) + 0x3930E - 0x14
    print(ecx)


def crackme83():
    serial = [0x71, 0x18, 0x59, 0x1B, 0x79, 0x42, 0x45, 0x4C]
    result = []
    result_str = ''
    for xor_value in range(0, 0xFF):
        temp = [i ^ xor_value for i in serial]
        print(temp)
        val1 = 0
        for j in temp:
            val1 ^= j
        if val1 == xor_value:
            result.append(temp)
    print("本题有{}解".format(len(result)))
    for i in result:
        for j in i:
            result_str += chr(j ^ 0x32)
    print(result_str)
    # 正推
    # name = 'wa1ex'
    # changed_name = []
    # c2 = []
    # for i in range(0, 8):
    #     try:
    #         changed_name.append(ord(name[i]) ^ 0x32)
    #     except:
    #         changed_name.append(0x32)
    # for i in range(0, 8, 2):
    #     c2.append(changed_name[i] ^ changed_name[i+1])
    # al = c2[0]
    # bl = c2[1]
    # al ^= bl
    # bl = c2[2]
    # cl = c2[3]
    # bl ^= cl
    # al ^= bl
    # for i in range(0, 8):
    #     changed_name[i] ^= al
    # print(changed_name)


def crackme85():
    name = 'fatestede'
    serial_str = "2611791907107919791926117919071078563412F0DEBC9A3434121278787878C6CCC6CC00CC00CCFFEFEFFF5555CCDD89876767CCCBCECEAB99887766773344"
    eax = 1
    esi = 0
    edx = len(name)
    for i in name:
        ecx = ord(i)
        edi = eax - 1
        ecx *= edi
        esi += ecx
        eax += 1
    ebx = (edx * 2 + 0x63) & 0xFFFF
    esi &= 0xFFFF
    ebx <<= 0x10
    esi += ebx
    esi &= 0xF
    ebx = esi * 4 * 2
    init_result = serial_str[ebx:ebx+8]
    result = ''
    for i in range(0, 8, 2):
        result = init_result[i:i+2] + result
    print(eval('0x' + result))


def crackme86():
    # 第一位hardcode
    hardcode = [0x48, 0x54, 0x2d, 0x37]
    pos1to4 = 'HT-7'

    # 第二位
    # 第5,7,10,11位相同 1111
    # 用户名ascii码累加后除以用户名长度和第6位相同 d
    name = 'wwa1ex'
    total = 0
    for i in name:
        total += ord(i)
    pos6 = chr(total // 6)
    pos5to11 = '1' + pos6 + '1' + name[1] + name[-2] + '11'
    # 第8、9位的和 和 用户名的第2位和倒数第2位的和 相等
    # 第10位和第11位的和除2余0（可忽略，因为10和11相同）

    # 第三位
    # 用户名长度模3为0 第12位操作了半天没发现有啥用
    # 第13位和6位的和 整除除以2
    # 第13、14、15位的和 + 用户名长 = 0x10A
    # 第16位和用户名的倒数第2位一致
    pos12 = 'w'
    pos13 = chr(ord(pos6) + 1)
    pos14 = chr((0x10A - len(name) - ord(pos13))//2)
    pos15 = chr(0x10A - len(name) - ord(pos13) - ord(pos14))
    pos16 = name[-2]
    pos12to16 = pos12 + pos13 + pos14 + pos15 + pos16
    print(pos1to4 + pos5to11 + pos12to16)


def crackme87():
    name = 'wa1ex'
    hex_name = []
    for i in name:
        ascii_num = hex(ord(i))
        hex_name.append(ord(ascii_num[2]))
        hex_name.append(ord(ascii_num[3]))
    hex_name.append(0)
    print(hex_name)

    esi = 1
    edi = 0
    pos_4034A2 = 0
    i = 0
    changed_str = []
    while i < len(hex_name) - 1:
        al = hex_name[i]
        bl = hex_name[i+1]
        if al == bl:
            esi += 1
            pos_4034A2 += 1
            i += 1
            if pos_4034A2 != 1:
                edi -= 2
                esi += 1
        else:
            if pos_4034A2 <= 1:
                pass
            else:
                edi -= 2
            pos_4034A2 = 0
            esi = 1
        eax = al << 8
        edx = esi + eax
        i += 1
        if edi >= len(changed_str):
            changed_str.append(hex(esi))
            changed_str.append(hex(al))
        else:
            changed_str[edi] = hex(esi)
            changed_str[edi+1] = hex(al)
        edi += 2
        if hex_name[i] == 0:
            break
    print(changed_str)

    pos_40331C = len(changed_str)
    changed_str2 = []
    edx = 0
    i = 1
    esi = 1
    while i <= len(name):
        ebx = (eval(changed_str[esi]) << 8) + eval(changed_str[esi-1])
        eax = ord(name[i-1])
        eax = eax + ebx - i
        edx = eax % i
        eax //= i
        eax -= pos_40331C
        ebx += i
        eax += edx
        eax ^= ebx
        changed_str2.append(eax & 0xFF)
        esi += 1
        if esi >= pos_40331C:
            esi = 1
        i += 1
    print(changed_str2)
    edx = len(name) * 2
    esi = ecx = 0
    serial = ''
    while esi != edx:
        ebx = bl = changed_str2[ecx]
        bl >>= 4
        al = bl
        al &= 0xF
        al += 0x30
        if al > 0x39:
            al += 7
        serial += chr(al)
        esi += 1
        al = (ebx & 0xFF)
        al &= 0xF
        al += 0x30
        if al > 0x39:
            al += 7
        ecx += 1
        serial += chr(al)
        esi += 1
    print(serial)


def crackme89():
    name = 'wa1ex'
    magic_str1 = 'IIII$9999'
    serial = ''
    for i in magic_str1:
        serial += chr(ord(i) ^ 0x9)
    print(serial)
    # @@@@-0000


def crackme90():
    name = 'wa1ex'
    magic_list = [0xEF, 0xCA, 0x69, 0xD0, 0xF9]
    changed_name = []
    for i in name:
        changed_name.append((ord(i) ^ 0x3) * 2)
    print(changed_name)
    edi = 0x12
    i = 0
    while edi != 0:
        dl = magic_list[i]


def crackme91():
    name = 'wa1ex'
    magic_str = 'biq2jrxc-ape3*dsynhz8gt5o7f0uml4v19w6+/k'
    trans_str = ''
    for i in name:
        eax = ord(i)
        ecx = eax * 5
        eax = ecx * 8 + eax
        ecx = 0x28
        edx = eax % ecx
        eax //= ecx
        dl = ord(magic_str[edx])
        trans_str += chr(dl)
    print(trans_str)
    magic_str2 = '-apeoiq2jrml4xcsw6ynh7f0uv19+3/k*dbz8gt5'
    for i in name:
        ecx = ord(i)
        eax = ecx
        eax <<= 0x5
        eax -= ecx
        ecx = 0x28
        edx = eax % ecx
        dl = ord(magic_str2[edx])
        trans_str += chr(dl)
    print(trans_str)
    magic_str3 = 'h7f0uv19+3/kjrml4xcsw6yn*dbz8gt5-apeoiq2'
    for i in range(0, len(trans_str)):
        eax = ord(trans_str[i])
        ecx = eax * 5
        eax = eax + 2 * ecx
        ecx = 0x28
        edx = eax % ecx
        dl = ord(magic_str3[edx])
        trans_str = trans_str[:i] + chr(dl) + trans_str[i+1:]
    print(trans_str)


def crackme93():
    name = 'wa1ex'
    serial = ''
    edx = 0x12DFD16
    for i in name:
        cl = (ord(i) ^ 0xCA) & 0xFF
        edx += cl
    edx ^= 0x19840808
    print(hex(edx)[2:])


def crackme94():
    # 要求serial的第一个ascii值能整除4536
    # print(0x11CF - 0x17) 4536 2 2 2 3 3 3 3 7
    # 必须是T，算法里硬加了个T出来
    # print(ord('T')) 84
    # 注册机写完了验证通用性的时候发现对输入还有要求
    name = 'wa1ex'
    ebx = len(name)
    edi = 0x2BC
    esi = 0x30
    eax = 0x48
    eax //= ebx
    esi -= eax
    esi *= 5
    edi -= esi
    edi = edi * 0x6B - 0xCF6C
    if edi > 0x2300:
        print("烂名字，改名吧\n")
        return
    elif edi >= 0x190:
        pass
    else:
        print("烂名字，改名吧\n")
        return
    temp = ''
    serial = 'T'
    magic_list = [0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
                  0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A]
    name_value = 0
    for i in name:
        name_value += ord(i)
    for i in range(0, len(name)):
        edi = ord(name[i])
        ecx = (i << 2)
        edx = i + 1
        ecx -= edx
        ecx = magic_list[ecx + 1]
        edx = edi
        edx ^= ecx
        ecx = name_value
        ecx *= i
        ecx -= name_value
        esi = ecx
        # esi ^= 0xFFFFFFFF
        esi = -esi - 1
        esi = esi + edx + 0x14D
        ecx = len(name)
        edx = i + 3
        ecx *= edx
        ecx *= edi
        eax = esi
        eax += ecx
        ecx = 0xA
        edx = eax % ecx + 0x30
        edi = edx ^ 0xADAC
        esi = i + 2
        eax = edi
        eax *= esi
        edx = eax % 0xA + 0x30
        temp += chr(edx)
    eax = len(name) * name_value
    ecx = 0x64
    edx = eax % ecx + 0x30
    temp = 'T' + temp + '-' + str(edx)
    for i in range(1, len(temp)):
        edi = ord(temp[i])
        eax = edi
        eax ^= 0x20
        ecx = 0xA
        edi = eax % ecx + 0x30
        serial += chr(edi)
    print(serial)


def crackme95():
    # 原代码没有从本质上理解问题，导致许多sb错误而且及其臃肿，参考ede代码如下
    magic_list1 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03, 0xFE, 0xFF, 0xFF, 0x07, 0xFE, 0xFF, 0xFF, 0x07, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    magic_list2 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0x07, 0xFE, 0xFF, 0xFF, 0x07, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    # python实现bt指令
    def bt(a, b):
        word = a[b//8]
        index = b % 8
        mask = 1 << index
        if word & mask != 0:
            return 1
        else:
            return 0

    # 确认check得出的有效范围
    start_pos = 0
    flag = 0
    for i in range(0, 255):
        if bt(magic_list1, i) and flag == 0:
            start_pos = i
            flag = 1
        if not bt(magic_list1, i) and flag == 1:
            flag = 0
            # check1(local17)
            print("check1允许范围{}-{}".format(chr(start_pos), chr(i-1)))
    # check2(local25)只允许大小写英文字母了

    # 用户名存在三次变形
    name = 'abcda'
    name_reverse = name[::-1]
    list_name = list(name)
    list_name.sort()
    name_sort = ''.join(list_name)
    total_name = name + name_reverse + name_sort

    # 算了一下偏差的范围在[-7,-26]
    length = len(name)
    bias_list = []
    # check1
    for i in range(0, length):
        edx = length * 3
        eax = (i+1) * 2
        edx -= eax
        edx -= 0x14
        bias_list.append(edx)

    # check2
    for i in range(0, length):
        edx = length * 3
        eax = (i+1) * 3
        edx -= eax
        edx -= 0x14
        bias_list.append(edx)

    # check3
    for i in range(0, length):
        eax = length - 3
        edx = eax * eax
        eax = (i+1) * 2
        edx -= eax
        edx -= 0x14
        bias_list.append(edx)
    print(bias_list)

    # 最终目的是：让正序用户名、倒序用户名、sort用户名在进行bias_list对应变换后仍然为大、小写字母
    serial = ''
    for i in range(0, len(total_name)):
        temp = chr(ord(total_name[i]) + bias_list[i])
        if temp.isalpha():
            serial += temp
        else:
            print('out of range!change your name!')
            return
    print(serial)


def crackme96():
    name = 'walex'
    local5 = 0x4D
    local6 = 0x60FF58
    local7 = 0x401220
    local8 = 0x401220
    for i in name:
        edx = ord(i)
        local5 = 80 * edx + local5
        local6 = (local5 + local6) ^ 0x32
        local7 = local6 * 4 + local7
        local8 = local5 + local6 + local7
    print(hex(local8)[2:])


def crackme98():
    name = 'walex'
    serial = ''
    hardcode1 = 'A1LSK2DJF4HGP3QWO5EIR6UTYZ8MXN7CBV9'
    hardcode2 = 'SU7CSJKF09NCSDO9SDF09SDRLVK7809S4NF'
    for i in name.upper():
        index = hardcode1.find(i)
        serial += hardcode2[index]
    print(serial)


def crackme99():
    name = 'fasseded'
    serial = '12345678'
    esi = len(name)
    ebx = len(serial)
    result_list = []
    for i in range(0, esi):
        edx = ord(name[i])
        edx ^= i
        ecx = ebx
        ecx ^= i
        edx += ecx
        result_list.append(edx)
        print(edx)
        # 好像是会把小于0x20 大于0x80的归一化，略
    result_str = ''
    for i in result_list:
        result_str += chr(i)
    # 由于程序里比对的顺序是反的，所以这里也得反一下
    print(result_str[::-1])


def crackme100():
    serial = ''
    machine_code = 0
    magic_code1 = 0x4B4EB28
    magic_code2 = 0x22F16632
    magic_code3 = 0x2CF062E0
    magic_code4 = 0x6C21D6B
    serial += str(magic_code1 ^ machine_code)[1:5]
    serial += str(magic_code2 ^ machine_code)[1:5]
    serial += str(magic_code3 ^ machine_code)[1:5]
    serial += str(magic_code4 ^ machine_code)[1:5]
    print(serial)


def crackme101():
    # 0xA 0x31-0x39
    # ww-1w393w011
    print(0x48 ^ 0xC)
    hardcode = {2: 0x2D, 3: 0x31, 5: 0x33, 6: 0x39, 7: 0x33, 9: 0x30, 0xA: 0x31, 0xB: 0x31}
    # 1,4,8位 + 用户名长为0xAB 171
    code = 'x5-153935011'
    ebx = 0x401115
    for i in code:
        value = ord(i)
        ah = value % 2
        if not ah:
            ebx += 0x100
    edx = len(code)
    ebx <<= 0x8
    index = 0x1
    cl = 0x2
    while index < len(code):
        bl = ord(code[index])
        edx += bl
        cl += 1
        index += cl
    for i in hardcode.keys():
        code = code[:i] + chr(hardcode[i]) + code[i+1:]
    print(code)


def crackme102():
    origin_str = '11111-11111-11111-11111-11111'
    base = 0x4031D0
    Word_2D = [0x4031D5, 0x4031DB, 0x4031E1, 0x4031E7]
    for pos in Word_2D:
        print(pos - base + 1)


def crackme103():
    name = 'walex'
    eax = 1
    for i in name:
        bl = ord(i)
        eax = (eax * bl) & 0xFFFFFFFF
        eax ^= 0x63546D32
        print(hex(eax))
    eax >>= 1
    serial = ''
    for i in range(len(hex(eax))-2, 1, -2):
        serial += hex(eax)[i:i+2]
    print(serial)


def crackme104():
    hardcode1 = '668r9\\5233'
    hardcode2 = '-'
    hardcode3 = 'k329[43}'
    name = 'fatestede'
    esi = len(name)
    edi = esi * 0x75 + 0x153E - 0x1574
    eax = (esi - 0x22) * 0x11F0
    edi = edi + eax + 0xE524C
    serial = hardcode1 + str(edi) + hardcode2 + hardcode3 + hex(ord(name[0]))[2:] + '$'
    print(serial)


def crackme105():
    pos_4030C4 = 0
    name = 'walex'
    ebx = 0x1
    for i in range(len(name)-1, -1, -1):
        edx = ord(name[i])
        edx ^= ebx
        edx *= ebx
        ebx += 5
        pos_4030C4 ^= edx
        for j in range(0, 5):
            pos_4030C4 = rol(pos_4030C4)
    pos_4030C4 = 0xFFFFFFFF - pos_4030C4
    for i in name:
        pos_4030C4 = ror(pos_4030C4)
    print(hex(pos_4030C4))
    ebx = pos_4030C4
    list_serial_front = []
    while ebx != 0:
        edx = (ebx % 0x1A) + 0x41
        ebx = (ebx - ebx % 0x1A) // 0x1A
        list_serial_front.append(edx)
    str_serial = ''
    for i in range(len(list_serial_front) - 1, -1, -1):
        str_serial = chr(list_serial_front[i]) + str_serial
    print(str_serial)
    str_serial += '-'
    pos_4030C9 = 1
    pos_4030CA = 2
    pos_4030CB = 3
    # 蚌埠住了，三元一次方程来了
    pos_4030CC = pos_4030C9 * 3 - pos_4030CA + pos_4030CB * 5
    pos_4030D0 = -pos_4030C9 * 7 + pos_4030CA * 2 + pos_4030CB * 7
    pos_4030D4 = pos_4030C9 + pos_4030CA - pos_4030CB * 2
    from sympy import symbols, Eq, solve
    x, y, z = symbols('x,y,z')
    eq1 = Eq((3 * x - y + z * 5), 0x204)
    eq2 = Eq((-7 * x + 2 * y + 7 * z), 0x19)
    eq3 = Eq((x + y - 2 * z), 0xD)
    ans = (solve((eq1, eq2, eq3), (x, y, z)))
    print(ans)
    for i in ans.keys():
        str_serial += chr(ans[i])
    print(str_serial)


def crackme106():
    serial = 'wwalex'
    serial = serial.upper()
    name = ''
    for i in range(0, len(serial), 2):
        cl = ord(serial[i+1])
        al = ord(serial[i])
        al -= 0x41
        cl -= 0x41
        esi = cl
        cl = al
        ebx = 0x1A
        edx = cl * 9
        eax = edx + 2 * esi
        edx = eax % ebx
        eax //= ebx
        name += chr(edx + 0x41)
        eax = 3 * esi
        cl += 4 * eax
        eax += cl
        edx = eax % ebx
        name += chr(edx + 0x41)
    print(name)


def crackme107():
    hardcode1 = 'qwgboy2000'
    hardcode2 = 'PVFANX'
    hardcode3 = 'cool'
    serial = ''
    serial += hardcode1
    for i in range(0, len(hardcode2)):
        serial += chr(ord(hardcode1[i]) - ord(hardcode2[i]))
    serial += hardcode3
    print(serial)


def crackme108():
    name = 'fatestede'
    hardcode = [0x13, 0x16, 0x99, 0x11, 0x63, 0x15, 0x54, 0x52, 0x88, 0x01, 0x31, 0x56, 0x68, 0x55, 0x37]
    local1 = 0
    for i in range(0, len(name)):
        ecx = ord(name[i])
        eax = hardcode[i+1] + local1
        eax += ecx
        local1 = eax
        edx = ecx * 0xA
        eax = local1
        eax += edx
        local1 = eax
    print(hex(local1))
    local2 = 0
    for i in range(0, len(name)):
        ecx = hardcode[i] * 0xA
        edx = local2
        edx += ecx
        local2 = edx
        eax = ord(name[2])
        edx = hardcode[i]
        edx += local2
        edx += eax
        edx += 0x31337
        local2 = edx
    print(hex(local2))
    serial1 = '-aboo-me-'
    serial2 = '-SCA'
    serial = hex(local1)[2:].upper() + serial1 + hex(local2)[2:].upper() + str(local2) + serial2
    print(serial)


def crackme109():
    name = 'walex'
    esi = 0
    ebx = 0
    for i in range(0, 2):
        edx = esi ^ 0x2
        ebx = ord(name[edx])
        eax = ord(name[edx-1])
        ebx |= eax
        ebx += len(name)
        esi += 1
    print(ebx)


def crackme110():
    # 0x1D5
    serial1 = 'WALEXT'
    # 0x1B2
    serial2 = 'WALEX1'
    serial = serial1
    name = 'alex'
    for i in range(0, len(name)):
        serial += chr(ord(serial1[i]) ^ ord(name[i]))
    serial += serial2
    print(serial)


def crackme111():
    name = 'walex'
    name = name.upper()
    di = 0
    ax = 0
    for i in name:
        ax = ord(i) - 0x40
        ax *= 0x82
        ax += di
        ax += 16 * 0x50
        di = ax
    print(ax)


def crackme112():
    serial = '12345678901234'
    serial1 = ''
    for i in serial:
        serial1 += str(ord('4') ^ ord(i))
    print(serial1)


def crackme113():
    return

def crackme116():
    name = 'walexw'
    ecx = 0
    for i in name:
        al = ord(i)
        ecx += al
        for j in range(0, 8):
            ecx = rol(ecx)
    ecx ^= 0x2
    ecx -= 0x50
    ecx ^= 0x1337
    si = 0x07E8
    # 这个位置可能会溢出
    ecx += si
    print(ecx)


def crackme117():
    name = 'walex'
    eax = ord(name[0])
    eax ^= 0xE
    print(str(eax)+str(len(name)))


def crackme118():
    ebp = 0
    name = 'fatestede'
    serial = name[0] + '-' + name[-1].upper()
    for i in name:
        ecx = ord(i)
        ebp += ecx
    ebp += 0x6064
    print(ebp)
    serial = serial + str(ebp) + '-'
    ebp += 0x6064
    print(ebp)
    serial = serial + str(ebp)
    print(serial)


def crackme119():
    name = 'walex1'
    pos_448830 = 0
    total = 0
    hardcode = 'p:\\4.Nulaei tmc!'
    index = [15, 2, 3, 13, 14, 1, 4, 13, 14, 1]
    for i in index:
        total += ord(hardcode[i-1])
    for i in name:
        pos_448830 += ord(i)
    pos_448830 = pos_448830 + 0xA + 0xD
    eax = pos_448830
    eax += 0x246
    pos_448834 = eax
    eax >>= 1
    pos_448838 = eax
    pos_44883C = eax * eax
    pos_448840 = pos_44883C - 0x1E5B
    print(hex(pos_448830))
    print(hex(pos_448834))
    print(hex(pos_448838))
    print(hex(pos_44883C))
    print(hex(pos_448840))
    print(pos_448840)


def crackme120():
    eax = 0
    name = 'walex'
    local6 = len(name)
    for i in name:
        eax += ord(i)
    ecx = -eax
    edx = eax + len(name)
    # 这里如果按位与会把符号位的1保存下来
    local3 = ecx * edx
    serial = 0
    while True:
        local4 = - serial
        edx = local4 * local4
        eax = local4 * local6
        if edx + eax + local3 == 0:
            # 550
            print('answer is: ' + str(serial))
            return
        serial += 1


def crackme121():
    name = 'walex'
    pos_45B844 = 0
    for i in name:
        edx = ord(i)
        edx = ((edx << 3) & 0xFFFFFFFF)
        pos_45B844 += edx
    eax = (len(name) << 0x3)
    pos_45B844 += eax
    eax = pos_45B844 << 0x2
    print(eax)


def calc122(num):
    if num >= 2 ** 31:
        return 0xFFFFFFFF - num + 1
    else:
        return num


def crackme122():
    name = 'walex'
    serial = ''
    name_len = len(name)
    ebx = 0
    for i in range(0, name_len):
        ecx = (name_len * 0x21C6918E)
        ebx = ebx + ecx
        ecx = ord(name[i]) * 0x2CE
        ebx = ebx + ecx
    ebx &= 0xFFFFFFFF
    serial += str(calc122(ebx)) + '-'

    for i in range(0, name_len):
        ecx = ord(name[i])
        ecx = ecx * 0x21C6918E * 0x7BC
        ebx = ebx + ecx - name_len
    ebx &= 0xFFFFFFFF
    serial += str(calc122(ebx)) + '-'

    for i in range(0, name_len):
        ecx = ord(name[i])
        ecx = ecx * name_len * 0x4C6
        ebx = ebx + ecx + name_len
    ebx = (ebx + 0x21C6918E) & 0xFFFFFFFF
    serial += str(calc122(ebx))
    print(serial)


def crackme123():
    name = 'walex'
    eax = 0x29A
    for i in name:
        ecx = ord(i)
        esi = ecx ^ 0xDADA
        esi += eax
        eax = ecx
        eax ^= 0xBABE
        ecx ^= 0xF001
        eax = 0xFFFFFFFF - eax
        if eax + 4 * esi >= 0xFFFFFFFF:
            eax = eax + 4 * esi - 0xFFFFFFFF
        else:
            eax = eax + 4 * esi
        eax >>= 3
        eax += ecx
    eax += 0x28F
    ecx = 0x1234
    eax %= ecx
    for i in range(0, 0x10001):
        if ((eax * i) & REGISTER_MAX) % 0x10001 == 1:
            print(hex(i))


def crackme124():
    target = 0x3ADAFFCF
    target_lor = 0xFFCF3ADA
    serial = target_lor ^ 0xDEAF
    # 补码
    serial = REGISTER_MAX - serial + 1
    # ah有进位
    serial += 0xE000
    print(serial)


def crackme125():
    name = 'walex'
    company = 'arknight'
    hardcode = [0x2c, 0x61, 0x23, 0x47, 0x0E, 0x26, 0x61, 0x20, 0x31, 0x49, 0x36, 0x24, 0x2b, 0x42, 0x31, 0x63, 0x0E, 0x29, 0x5e, 0x30, 0x4b, 0x38, 0x2a, 0x33, 0x44, 0x3d]
    ebp_C = hardcode[ord(name[0])-ord('a')]
    esi = hardcode[ord(name[2])-ord('a')]
    edi = hardcode[ord(company[-2])-ord('a')]
    eax = hardcode[ord(company[-1])-ord('a')]
    edx = hardcode[ord(name[3])-ord('a')]
    ecx = hardcode[ord(company[2]) - ord('a')]
    edx *= ecx
    ebp_8 = edx
    edx = ebp_C * esi * edi * eax + ebp_8
    eax = (edx ^ 0x28D8) + 0x288D4A7D
    ecx = 0x3039
    for i in range(0, 6):
        ecx = rol(ecx)
    eax ^= 0x9714
    for i in range(0, 2):
        eax = ror(eax)
    eax >>= 3
    eax += ecx + ebp_8 + 1
    temp = eax % 0x10000
    temp = 0xFFFF - temp
    eax = eax - (eax % 0x10000) + temp
    eax += 0x29A
    print(eax)


def crackme126():
    # name = 'walex'
    # name_len = len(name)
    # serial = '12345'
    # serial_len = len(serial)
    # temp1 = []
    # for i in range(0, name_len):
    #     temp1.append(ord(name[i]) ^ ord(serial[i]))
    # al = serial[serial_len >> 1]
    # temp2 = []
    # for i in range(0, name_len):
    #     dl = temp1[i]
    #     dl ^= ord(al)
    #     temp2.append(dl)
    # temp3 = []
    # for i in range(0, name_len):
    #     dl = temp2[i]
    #     if ord(al) >= 0x41:
    #         dl ^= ord(al) - 0x41
    #     else:
    #         dl ^= ord(al) + 0x100 - 0x41
    #     temp3.append(dl)
    # temp4 = []
    # for i in range(0, name_len):
    #     dl = temp3[i]
    #     al = name_len
    #     al += serial_len
    #     dl += al
    #     temp4.append(dl)
    # for i in temp4:
    #     print(hex(i))
    # name[i] = name[i] ^ serial[i] ^ serial[serial_len >> 1] ^ serial[serial_len >> 1] - 0x41 + name_len + serial_len = serial[i]
    # name[i] = (serial[i] - 2 * serial_len) ^ serial[i] ^ serial[serial_len >> 1] ^ serial[serial_len >> 1] - 0x41
    # 要写标准注册机的话得做遍历，方程多解
    serial = 'walex'
    serial_len = len(serial)
    name = ''
    for i in serial:
        name += chr((ord(i) - 2 * serial_len) ^ ord(i) ^ (ord(serial[serial_len >> 1])) ^ (ord(serial[serial_len >> 1]) - 0x41))
    print(name)


def crackme127():
    xor_code = 0xAD924AC0
    add_code = 0xDEAD
    mul_code = 0x2
    shr_code = 0x3
    sub_code = 0x1337
    target = 0x4010FB
    temp = (((target + sub_code) << shr_code) // mul_code - add_code) ^ xor_code
    serial = ''
    print(hex(temp))
    for i in range(8, 1, -2):
        if hex(temp)[i+1] >= 'a':
            if hex(temp)[i] == 'b':
                serial += '9' + hex(temp)[i+1]
            elif hex(temp)[i] == 'a':
                serial += '8' + hex(temp)[i+1]
            else:
                serial += chr(ord(hex(temp)[i])-2) + hex(temp)[i+1]
        else:
            serial += hex(temp)[i: i+2]
    print(serial)


def crackme128():
    serial = ''
    serial += chr(0x57) + chr(0x4F) + chr(0x57) + chr(0x5F) + chr(0x59) + chr(0x4F) + chr(0x55) + chr(0x5F)
    serial += chr(0x44) + chr(0x49) + chr(0x44) + chr(0x5F) + chr(0x49) + chr(0x54) + chr(0x21)
    print(serial)


def crackme129():
    num = 1
    sum = 0
    target = 0x141
    while True:
        if sum >= target:
            print('num is {}, extra value is {}'.format(num - 1, sum - target))
            break
        sum += num
        num += 1

    name = 'walexwalexwalexwalexwalex'
    serial = 'zzzzzzzzzzzzzzzzzzzzzezzz'


def crackme130():
    ebx = 0x49390305
    esi = 0x48631220
    name = 'walex'
    for i in name:
        cl = ord(i)
        ebx ^= cl
        esi ^= ebx
        if ebx & 0x1:
            ebx >>= 1
            ebx ^= 0x1200311
        else:
            ebx >>= 1
    ebx = (10 - len(hex(ebx))) * '0' + hex(ebx)[2:]
    esi = (10 - len(hex(esi))) * '0' + hex(esi)[2:]
    serial = ebx[4:] + '-' + ebx[:4] + '-' + esi[4:] + '-' + esi[:4]
    print(serial.upper())


def crackme131():
    name = 'walex123'
    code = 33247872
    serial = 'TCRKM7-'
    hardcode = 'ANGBSZMLYFXRKWCcQDTIVOHPUE'
    #  hardcode[num] = serial[i]
    #  code = num - [i]
    for i in range(0, len(str(code))):
        num = int(str(code)[i]) + i
        serial += hardcode[num]

    # code only
    # 0x30 - 0x39
    index1 = [0x1, 0x2, 0x5, 0x6, 0x9, 0xA, 0xD, 0xE]
    # 0x61 - 0x7A
    index2 = [0x3, 0x4, 0xB]
    # 0x41 - 0x5A
    index3 = [0x7, 0x8, 0xC]
    # 12位组成的数字比56位大9
    # 90位组成的数组与56位相加为99
    # 13 14位组成的数与90位相加为66
    # 然后制定了其余各位的数值
    code = '72pv63LG36tX30'


def crackme132():
    hardcode = 'figugegl'
    name = 'yuukalex'
    serial = ''
    ecx = 0x7
    for i in range(0, len(name)):
        edx = ord(name[i])
        edx ^= ord(hardcode[ecx - i])
        edx %= 0x8
        serial += hardcode[edx]
    print(serial)


def crackme133():
    # 6 + 3 = 0xDD
    # 3 - 6 = 0x7
    # 4 - 5 + 1 = 0x25
    # 5 - 4 + 2 = 0x5E
    # 2 - 1 = 0x41
    # 5 = 0x61
    # 1 + ... + 7 = 0x24A
    serial = '!break$'


def crackme134():
    name = 'lovelyuuka'
    sum = 0
    for i in name:
        sum += ord(i)
    serial = sum * 0x539
    print(serial)


def crackme135():
    hardcode = 'ibetthatyoucantcrackthis'
    hardcode_hacker = 'i1b2e3t4t5h6a7t8y9o0ucantcrackthis'


def crackme136():
    eax = ebx = 0
    length = 6
    for i in range(0, length):
        eax <<= 1
        ebx = eax
        eax <<= 1
        eax <<= 1
        ebx += i + 1
        eax += ebx
    print(eax)
    print(0x3039)


def crackme137():
    serial = ''
    # 大
    serial += chr(0x47 + 1)
    # 小
    serial += chr(0x6D - 1)
    # 等
    serial += chr(0x56)
    # 等
    serial += chr(0x66)
    # 等
    serial += chr(0x33)
    # 大
    serial += chr(0x79 + 1)
    # 等
    serial += chr(0x38)
    # 小
    serial += chr(0x4E - 1)
    # 不等
    serial += 'y'
    # 等
    serial += chr(0x32)
    print(serial)


def crackme138():
    regkey = '123-567-911-W'
    pos_405670 = 0
    for i in range(1, 4):
        edx = 0xB - i
        pos_405670 += edx * (ord(regkey[i-1]) - 0x30)
    for i in range(5, 8):
        edx = 0xC - i
        pos_405670 += edx * (ord(regkey[i-1]) - 0x30)
    for i in range(9, 0xC):
        edx = 0xD - i
        pos_405670 += edx * (ord(regkey[i-1]) - 0x30)
    pos_405670 += ord(regkey[-1]) % 2
    print(pos_405670)

    name = 'walex'
    total = 0
    binary_one_num = 0
    for i in name:
        total += ord(i)
    while total:
        if total % 2 == 1:
            binary_one_num += 1
        total >>= 1
    print(binary_one_num)

    pos_40567C = 1
    for i in range(0, binary_one_num):
        pos_40567C *= 200
    pos_40567C &= 0xFFFFFFFF
    print(hex(pos_40567C))
    # pos_405674 = 0
    # pos_405678 = 1
    # serial = '12345'
    # serial = serial[::-1]
    # # 字符串转整数
    # for i in serial:
    #     eax = (ord(i) - 0x30) * pos_405678
    #     pos_405674 += eax
    #     pos_405678 *= 10
    # eax = 0x7A1200
    # eax %= pos_405674
    # print(eax)
    target_eax = 0x2
    for modulus in range(0x2710, 0x1869F):
        if pos_40567C % modulus == target_eax:
            print('模数为:{}'.format(modulus))


def crackme139():
    from sympy import isprime
    for i in range(10000000, 99999999):
        if isprime(i):
            print(i)
            break


def crackme140():
    name = 'yuukaw'
    str_hardcode = "36 37 38 39 30 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4" \
               "F 50 51 52 53 54 55 56 57 58 59 5A C1 C9 CD D3 DA C0 C8 CC D2 D9 C2 CA CE D4"
    hardcode = []
    for i in name:
        hardcode.append(ord(i))
    for i in range(0, len(str_hardcode)):
        if str_hardcode[i] == ' ':
            hardcode.append(eval('0x' + str_hardcode[i-2:i]))
        elif i == len(str_hardcode) - 1:
            hardcode.append(eval('0x' + str_hardcode[i-1:i+1]))
    reverse_hardcode = hardcode[::-1]
    print(hardcode)

    # pos_403CD8
    temp = 0
    eax = 0
    for i in range(0, len(hardcode)):
        eax = hardcode[i]
        eax = (eax + i + 1) * 2
        eax += temp
        temp = eax
    total = len(hardcode) + eax
    temp = 0
    for i in range(0, len(hardcode)):
        eax = reverse_hardcode[i]
        eax ^= total
        eax *= i + 1
        eax += temp
        temp = eax
        eax = (i + 1) ^ total
        eax |= temp
        temp = eax
    print(hex(eax))
    ebx = 0x1A
    serial = ''
    while temp:
        edx = temp % ebx
        temp //= ebx
        if edx < 0xA:
            serial += chr(0x30 + edx)
        else:
            serial += chr(0x37 + edx)
    serial += '-'
    print(serial)

    # pos_403C08
    temp = 0
    eax = 0
    for i in range(0, len(hardcode)):
        eax = hardcode[i]
        eax = (eax + i + 1) * 2
        eax += temp
        temp = eax
    total = len(hardcode) + eax
    temp = 0
    for i in range(0, len(hardcode)):
        eax = hardcode[i]
        eax ^= total
        eax *= i + 1
        eax += temp
        temp = eax
        eax = (i + 1) ^ total
        eax |= temp
        temp = eax
    print(hex(eax))
    ebx = 0x1A
    part_serial = ''
    while temp:
        edx = temp % ebx
        temp //= ebx
        if edx < 0xA:
            part_serial += chr(0x30 + edx)
        else:
            part_serial += chr(0x37 + edx)
    serial += part_serial[::-1] + '-'
    print(serial)

    # pos_4039C4
    str_hardcode1 = '31 32 33 34 35 36 37 38 39 30 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 5' \
                    '6 57 58 59 5A C1 C9 CD D3 DA C0 C8 CC D2 D9 C2 CA CE D4 DB C3 D5 C4 CB CF D6 DC DD C7 D1'
    hardcode1 = []
    hardcode2 = []
    for i in range(0, len(str_hardcode1)):
        if str_hardcode1[i] == ' ':
            hardcode1.append(eval('0x' + str_hardcode1[i-2:i]))
        elif i == len(str_hardcode1) - 1:
            hardcode1.append(eval('0x' + str_hardcode1[i-1:i+1]))
    for i in range(0, len(hardcode)):
        ecx = hardcode1[i] * 2
        edx = ecx + hardcode[i]
        hardcode2.append(edx & 0xFF)
    print(hardcode2)

    # pos_403C70
    temp = 0
    eax = 0
    for i in range(0, len(hardcode2)):
        eax = hardcode2[i]
        eax = (eax + i + 1) * 2
        eax += temp
        temp = eax
    total = len(hardcode2) + eax
    temp = 0
    for i in range(0, len(hardcode2)):
        eax = hardcode2[i]
        eax ^= total
        eax *= i + 1
        eax += temp
        temp = eax
        eax = (i + 1) ^ total
        eax |= temp
        temp = eax
    print(hex(eax))
    ebx = 0x1A
    part_serial = ''
    while temp:
        edx = temp % ebx
        temp //= ebx
        if edx < 0xA:
            part_serial += chr(0x30 + edx)
        else:
            part_serial += chr(0x37 + edx)
    serial += part_serial[::-1] + '-'
    print(serial)

    # pos_403D60
    hardcode2_reverse = hardcode2[::-1]
    for i in range(0, len(hardcode2_reverse)):
        eax = hardcode2_reverse[i]
        eax ^= total
        eax *= i + 1
        eax += temp
        temp = eax
        eax = (i + 1) ^ total
        eax |= temp
        temp = eax
    print(hex(eax))
    ebx = 0x1A
    part_serial = ''
    while temp:
        edx = temp % ebx
        temp //= ebx
        if edx < 0xA:
            part_serial += chr(0x30 + edx)
        else:
            part_serial += chr(0x37 + edx)
    serial += part_serial
    print(serial)


def crackme141():
    name = 'yuukaww'
    edx = 0x1
    ecx = 0
    for i in name:
        eax = ord(i)
        esi = eax
        eax = (eax * edx) & 0xFFFFFFFF
        esi ^= 0x32142001
        ecx = (ecx + esi) & 0xFFFFFFFF
        ebx = 0x7
        eax |= ecx
        esi = eax
        edx = eax % ebx
        ebx = 0x5
        edx += 0x2
        ecx = (ecx * edx) & 0xFFFFFFFF
        eax = ecx
        edx = eax % ebx
        edx += 0x3
        edx = (edx * esi) & 0xFFFFFFFF
    serial = (hex(ecx)[2:] + '-' + hex(edx)[2:]).upper()

    ecx = 1
    esi = 0
    edi = 0
    for i in name:
        eax = ord(i)
        edx = eax
        eax = (eax * ecx) & 0xFFFFFFFF
        edx |= 0xF001F001
        ecx = eax
        if esi < edx:
            esi = 0x100000000 - edx + esi
        else:
            esi -= edx
        edx = 0
        ebp = 0x7
        eax = ecx + esi
        ecx |= esi
        edi = (edi + eax) & 0xFFFFFFFF
        eax = edi
        edx = eax % ebp
        ebp = 0xB
        edx += 0x3
        ecx = (ecx * edx) & 0xFFFFFFFF
        ecx = (ecx + edi) & 0xFFFFFFFF
        edx = eax % ebp
        edx += 0x2
        edx = (edx * esi) & 0xFFFFFFFF
        edx = (edx + edi) & 0xFFFFFFFF
        esi = edx
        print(hex(ecx), hex(esi))
    serial += '+' + (hex(esi)[2:] + '-' + hex(ecx)[2:]).upper()
    print(serial)


def crackme142():
    computer_name = "Win10-2022JMXRUAdministrator"
    computer_name = computer_name[::-1].upper()
    name = 'walex'
    local1 = 0
    local2 = 0x1791117
    for i in name:
        edx = ord(i)
        edx += local2
        local1 += edx
        local2 += 1
    esi = len(name) * local1
    esi += local2

    local6 = len(name)
    local3 = 0
    eax = 0x20
    for i in computer_name:
        ecx = ord(i)
        ecx ^= eax
        ecx *= local6
        local3 += ecx
        eax += 1
    check1 = local3 + esi
    serial = check1 ^ local3
    print(serial)


def crackme143():
    str_hardcode = 'FE FA DD E1 E9 D5 EC E1 D9 FE FB D5 FE 01 EE F1 EA D5 F8 ED F6 FE D9 D5 F0 DD F7 F5 EB'
    hardcode = []
    for i in range(0, len(str_hardcode)):
        if str_hardcode[i] == ' ':
            if eval('0x' + str_hardcode[i-2:i]) < 0x10:
                hardcode.append(eval('0x1' + str_hardcode[i-2:i]))
            else:
                hardcode.append(eval('0x' + str_hardcode[i-2:i]))
        elif i == len(str_hardcode) - 1:
            if eval('0x' + str_hardcode[i-1:i+1]) < 0x10:
                hardcode.append(eval('0x1' + str_hardcode[i-1:i+1]))
            else:
                hardcode.append(eval('0x' + str_hardcode[i-1:i+1]))
    dis = max(hardcode) - 0x7E
    while max(hardcode) - dis <= 0x7E and min(hardcode) - dis >= 0x20:
        total = 0
        for i in hardcode:
            total += i - dis
        if total & 0xFF == dis:
            serial = ''
            for i in hardcode:
                serial += chr(i - dis)
            print(serial)
            return
        dis += 1

crackme143()
