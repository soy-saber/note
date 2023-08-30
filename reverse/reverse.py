
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


def rol(number):
    if (number * 2) > 0xFFFFFFFF:
        number = ((number * 2) & 0xFFFFFFFF) + 1
        return number

    else:
        return number * 2


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



crackme83()