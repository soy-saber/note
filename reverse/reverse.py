
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

crackme39()
