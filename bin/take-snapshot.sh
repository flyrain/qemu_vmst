./qemu -hda ~/fs_traverse/debian6_encrypt-target.qcow2  -hdb ~/fs_traverse/debian6_encrypt-ff.qcow2 -m 256  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22  -loadvm original

