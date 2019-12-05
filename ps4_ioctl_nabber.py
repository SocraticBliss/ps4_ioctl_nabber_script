#!/usr/bin/env python
import idaapi as ida
import idautils as idat

'''

PS4 IOCTL Nabber by SocraticBliss (R)

ps4_ioctl_nabber.py: An IDA script that saves the ioctl requests to an output file

'''

def nab(address, IOCTL = {}):
    
    for xref in idat.CodeRefsTo(address, True):
        name   = ida.get_func_name(xref)
        offset = xref
        
        count = 0
        while count < 16:
            if ida.tag_remove(ida.print_operand(offset, 0)) == 'esi':
                request = ida.tag_remove(ida.print_operand(offset, 1))[:-1]
                if len(request) != 8: 
                    request = request[1:]
                break
            
            offset -= 0x1
            count += 1
            
        IOCTL[name] = request
    
    return IOCTL


# PROGRAM START

if __name__ == '__main__':

    filename = idaapi.get_root_filename().split('.')[0]
    
    print('# PS4 IOCTL Nabber')
    print('# Searching for ioctl requests...')
    
    for function in idat.Functions():
        if 'ioctl' in ida.get_func_name(function):
            IOCTL = nab(function)
            
            if IOCTL:
                filename = ida.ask_file(True, 'Text files|*.txt|All files (*.*)|*.*', 'Where do you want to save your ioctl requests?')
                if filename != None:
                    print('# Saving ioctl requests...')
                    with open(filename, 'w') as OUTPUT:
                        for key, value in sorted(IOCTL.items(), key = lambda kv:(kv[1], kv[0])):
                            OUTPUT.write('%s %s\n' % (value, key))
                else:
                    print('# Printing them instead...')
                    for key, value in sorted(IOCTL.items(), key = lambda kv:(kv[1], kv[0])):
                        print(value + ' ' + key)                    
            else:
                print('# ioctl was not found or no named functions found!')
            
            break
    
    print('# Done!')

# PROGRAM END
