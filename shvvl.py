import hashlib

def shvvl(tag: str, bpf: int) -> bytes:
    '''
    This is SHVVL. The only important thing is that the "type" of node is the first string in the tag
    '''

    sectors = tag.split("\0")
    typehash = hashlib.md5(bytes(sectors[0], "UTF8"), usedforsecurity=False).digest()

    out = bytearray()
    hashfunc = hashlib.new('shake_256', usedforsecurity=False)
    for sector in sectors:
        hashfunc = hashlib.new('shake_256', usedforsecurity=False)
        
        blockInput = bytearray(sector, "UTF8")
        blockInput = blockInput + typehash
        hashfunc.update(blockInput)
        out += hashfunc.digest(bpf)

    print(out.hex())
    return out

def shvvl_float(tag: str, bpf: int) -> list[float]:
    out = list()
    for bite in shvvl(tag, bpf):
        for l in range(8):
            out.append(1.0 if (bite&(1<<l)) != 0 else 0.0)
        
    print(out)
    return
    


if __name__ == "__main__":
    shvvl_float("hey\0hello\0world", 5)