import numpy as np
import re

text = open('table6.txt').read()
text = re.sub("\n", " ", text)
text_list = text.split(", ")
letter = text_list[0][0:3]
for i in range(len(text_list)):
    text_list[i] = re.sub(letter,'', text_list[i])
zero_list = []
one_list = []
letter_list = []
for t in text_list:
    if re.match('[0-9]+ = 0', t):
        zero_list.append(int(re.sub(' = 0', '', t)))
    elif re.match('[0-9]+ = 1', t):
        one_list.append(int(re.sub(' = 1', '', t)))
    elif re.match('[0-9]+ = [a-z]', t):
        letter_list.append(int(re.sub(' = [a-z][0-9]+,[0-9]+', '', t)))

zeros = ''
for i in range(1,33):
    if i in zero_list:
        zeros += '1'
    else:
        zeros += '0'
ones = ''
for i in range(1,33):
    if i in one_list:
        ones += '1'
    else:
        ones += '0'
letters = ''
for i in range(1,33):
    if i in letter_list:
        letters += '1'
    else:
        letters += '0'

print(letter[:-1])
print('na zero: ', hex(int(zeros[::-1], 2)))
print('na jeden: ',hex(int(ones[::-1], 2)))
print(f'na inną: ',hex(int(letters[::-1], 2)))