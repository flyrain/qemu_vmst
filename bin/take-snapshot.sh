#./qemu -hda ~/image/ubuntu/ubuntu-10.10.raw -m 512  -monitor stdio
#./qemu -hda ~/FC6dump.qcow  -m 256  -monitor stdio 
#./qemu -hda ~/image/ubuntu/ubuntu-4.9.backup  -m 256  -monitor stdio 
#./qemu -hda ~/FC6dump.qcow  -m 256  -monitor stdio 
#./qemu -hda ~/debian.qcow2  -m 256  -monitor stdio -net nic,model=rtl8139 -net user -s -loadvm debian
#./qemu -hda ~/image/debian/de.raw2 -m 256  -monitor stdio --snapshot -gdb tcp::2000 -s
#./qemu -hda ~/image/debian/de.raw2 -m 512 -monitor stdio  -gdb tcp::2000 -s


#./qemu -hda ~/fs_traverse/debian.qcow2  -m 256  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22
#./qemu -hda ~/fs_traverse/debian-truecrypt-target.qcow2  -hdb ~/fs_traverse/debian-truecrypt.qcow2 -m 256  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22
./qemu -hda ~/fs_traverse/debian6_encrypt-target.qcow2  -hdb ~/fs_traverse/debian6_encrypt-ff.qcow2 -m 256  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22 -boot menu=on 
