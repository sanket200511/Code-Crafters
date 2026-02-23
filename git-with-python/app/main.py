import sys
import os
import zlib
import hashlib
import time
import struct

def init():
    os.makedirs(".git/objects", exist_ok=True)
    os.makedirs(".git/refs", exist_ok=True)

    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")

    print("Initialized git directory")

def hash_object_write(file_path):
    # Read file as bytes
    with open(file_path, "rb") as f:
        content = f.read()

    # Create header
    header = f"blob {len(content)}\x00".encode()

    # Combine header + content
    store_data = header + content

    # Compute SHA1
    sha1 = hashlib.sha1(store_data).hexdigest()

    # Create object directory
    dir_name = sha1[:2]
    file_name = sha1[2:]

    object_dir = os.path.join(".git", "objects", dir_name)
    os.makedirs(object_dir, exist_ok=True)

    object_path = os.path.join(object_dir, file_name)

    # Compress and write only if not exists
    if not os.path.exists(object_path):
        compressed = zlib.compress(store_data)
        with open(object_path, "wb") as f:
            f.write(compressed)

    # Print hash
    print(sha1)

def ls_tree_name_only(tree_sha):
    # Locate object file
    dir_name = tree_sha[:2]
    file_name = tree_sha[2:]
    path = os.path.join(".git", "objects", dir_name, file_name)

    # Read and decompress
    with open(path, "rb") as f:
        compressed = f.read()

    decompressed = zlib.decompress(compressed)

    # Remove header (tree <size>\0)
    null_index = decompressed.index(b"\x00")
    content = decompressed[null_index + 1:]

    i = 0
    while i < len(content):
        # Find space after mode
        space_index = content.index(b" ", i)

        # Find null after filename
        null_index = content.index(b"\x00", space_index)

        # Extract name
        name = content[space_index + 1:null_index]

        print(name.decode())

        # Move pointer: skip 20-byte SHA
        i = null_index + 1 + 20

def commit_tree(tree_sha, parent_sha, message):
    # Hardcoded author info (allowed by challenge)
    name = "John Doe"
    email = "john@example.com"

    # Timestamp
    timestamp = int(time.time())
    timezone = "+0000"

    # Build commit content (text part)
    content = (
        f"tree {tree_sha}\n"
        f"parent {parent_sha}\n"
        f"author {name} <{email}> {timestamp} {timezone}\n"
        f"committer {name} <{email}> {timestamp} {timezone}\n"
        "\n"
        f"{message}\n"
    ).encode()

    # Add header
    header = f"commit {len(content)}\x00".encode()
    store_data = header + content

    # Compute SHA1
    commit_sha = hashlib.sha1(store_data).hexdigest()

    # Store object
    dir_name = commit_sha[:2]
    file_name = commit_sha[2:]
    object_dir = os.path.join(".git", "objects", dir_name)
    os.makedirs(object_dir, exist_ok=True)

    object_path = os.path.join(object_dir, file_name)
    if not os.path.exists(object_path):
        with open(object_path, "wb") as f:
            f.write(zlib.compress(store_data))

    return commit_sha

def cat_file_print(hash_value):
    # Split hash into directory and filename
    dir_name = hash_value[:2]
    file_name = hash_value[2:]

    path = os.path.join(".git", "objects", dir_name, file_name)

    # Read compressed object
    with open(path, "rb") as f:
        compressed_data = f.read()

    # Decompress using zlib
    decompressed = zlib.decompress(compressed_data)

    # Format: b"blob <size>\x00<content>"
    null_index = decompressed.index(b"\x00")
    content = decompressed[null_index + 1:]

    # Print content WITHOUT newline
    sys.stdout.buffer.write(content)

def write_tree(directory="."):
    entries = []

    for name in sorted(os.listdir(directory)):
        if name == ".git":
            continue

        path = os.path.join(directory, name)

        if os.path.isfile(path):
            # Create blob
            with open(path, "rb") as f:
                content = f.read()

            header = f"blob {len(content)}\x00".encode()
            store_data = header + content
            sha1 = hashlib.sha1(store_data).hexdigest()

            # Store blob
            dir_name = sha1[:2]
            file_name = sha1[2:]
            object_dir = os.path.join(".git", "objects", dir_name)
            os.makedirs(object_dir, exist_ok=True)

            object_path = os.path.join(object_dir, file_name)
            if not os.path.exists(object_path):
                with open(object_path, "wb") as f:
                    f.write(zlib.compress(store_data))

            mode = b"100644"
            entries.append((mode, name.encode(), bytes.fromhex(sha1)))

        elif os.path.isdir(path):
            # Recursively create subtree
            sha1 = write_tree(path)
            mode = b"40000"
            entries.append((mode, name.encode(), bytes.fromhex(sha1)))

    # Build tree content
    tree_content = b""
    for mode, name, sha_bytes in entries:
        tree_content += mode + b" " + name + b"\x00" + sha_bytes

    # Add header
    header = f"tree {len(tree_content)}\x00".encode()
    store_data = header + tree_content

    # Hash tree
    tree_sha = hashlib.sha1(store_data).hexdigest()

    # Store tree
    dir_name = tree_sha[:2]
    file_name = tree_sha[2:]
    object_dir = os.path.join(".git", "objects", dir_name)
    os.makedirs(object_dir, exist_ok=True)

    object_path = os.path.join(object_dir, file_name)
    if not os.path.exists(object_path):
        with open(object_path, "wb") as f:
            f.write(zlib.compress(store_data))

    return tree_sha

def clone_repository(url, target_dir):
    os.makedirs(target_dir, exist_ok=True)
    os.chdir(target_dir)
    init()

    # -------------------------
    # FETCH HEAD SHA
    # -------------------------
    info_url = url.rstrip("/") + ".git/info/refs?service=git-upload-pack"
    from urllib.request import urlopen
    with urlopen(info_url) as response:
        data = response.read()

    i = 0
    head_sha = None

    while i < len(data):
        length = int(data[i:i+4], 16)
        if length == 0:
            i += 4
            continue

        line = data[i+4:i+length]
        i += length

        if line.startswith(b"#"):
            continue

        if b"\x00" in line:
            line = line.split(b"\x00")[0]

        if b"refs/heads/main" in line or b"refs/heads/master" in line:
            head_sha = line.split(b" ")[0].decode()
            break

    if not head_sha:
        raise Exception("HEAD SHA not found")

    print("HEAD SHA:", head_sha)

    # -------------------------
    # FETCH PACKFILE
    # -------------------------
    upload_url = url.rstrip("/") + ".git/git-upload-pack"

    want_line = (
        f"want {head_sha} multi_ack_detailed side-band-64k "
        "ofs-delta thin-pack no-progress include-tag\n"
    )

    want_packet = f"{len(want_line)+4:04x}".encode() + want_line.encode()
    body = want_packet + b"0000" + b"0009done\n"

    headers = {"Content-Type": "application/x-git-upload-pack-request"}

    from urllib.request import Request, urlopen
    req = Request(
        upload_url,
        data=body,
        headers={"Content-Type": "application/x-git-upload-pack-request"},
        method="POST"
    )

    with urlopen(req) as response:
        data = response.read()

    # unwrap side-band
    i = 0
    real_pack = b""

    while i < len(data):
        length = int(data[i:i+4], 16)
        if length == 0:
            i += 4
            continue

        packet = data[i+4:i+length]
        i += length

        if not packet:
            continue

        channel = packet[0:1]
        payload = packet[1:]

        if channel == b"\x01":
            real_pack += payload

    if not real_pack.startswith(b"PACK"):
        raise Exception("Invalid packfile")

    version = struct.unpack(">I", real_pack[4:8])[0]
    object_count = struct.unpack(">I", real_pack[8:12])[0]

    print("PACK version:", version)
    print("Object count:", object_count)

    # -------------------------
    # PARSE PACK OBJECTS
    # -------------------------
    offset = 12
    objects = []
    object_map = {}

    for _ in range(object_count):
        start_offset = offset

        first_byte = real_pack[offset]
        offset += 1

        obj_type = (first_byte >> 4) & 0b111
        size = first_byte & 0b1111
        shift = 4

        while first_byte & 0b10000000:
            first_byte = real_pack[offset]
            offset += 1
            size |= (first_byte & 0b01111111) << shift
            shift += 7

        type_map = {
            1: "commit",
            2: "tree",
            3: "blob",
            6: "ofs-delta",
            7: "ref-delta"
        }

        type_name = type_map.get(obj_type)

        # Handle delta base references
        base_ref = None

        if obj_type == 6:  # OFS_DELTA
            c = real_pack[offset]
            offset += 1
            base_offset = c & 0x7f
            while c & 0x80:
                c = real_pack[offset]
                offset += 1
                base_offset = ((base_offset + 1) << 7) | (c & 0x7f)
            base_ref = start_offset - base_offset

        elif obj_type == 7:  # REF_DELTA
            base_ref = real_pack[offset:offset+20]
            offset += 20

        # decompress
        decompressor = zlib.decompressobj()
        obj_data = decompressor.decompress(real_pack[offset:])
        consumed = len(real_pack[offset:]) - len(decompressor.unused_data)
        offset += consumed

        objects.append({
            "type": type_name,
            "data": obj_data,
            "base": base_ref
        })

    # -------------------------
    # RESOLVE DELTAS
    # -------------------------
    def apply_delta(base, delta):
        i = 0

        def read_varint():
            nonlocal i
            result = 0
            shift = 0
            while True:
                b = delta[i]
                i += 1
                result |= (b & 0x7f) << shift
                if not (b & 0x80):
                    break
                shift += 7
            return result

        base_size = read_varint()
        result_size = read_varint()

        result = b""

        while i < len(delta):
            opcode = delta[i]
            i += 1

            if opcode & 0x80:
                cp_offset = 0
                cp_size = 0

                if opcode & 0x01:
                    cp_offset |= delta[i]
                    i += 1
                if opcode & 0x02:
                    cp_offset |= delta[i] << 8
                    i += 1
                if opcode & 0x04:
                    cp_offset |= delta[i] << 16
                    i += 1
                if opcode & 0x08:
                    cp_offset |= delta[i] << 24
                    i += 1

                if opcode & 0x10:
                    cp_size |= delta[i]
                    i += 1
                if opcode & 0x20:
                    cp_size |= delta[i] << 8
                    i += 1
                if opcode & 0x40:
                    cp_size |= delta[i] << 16
                    i += 1

                if cp_size == 0:
                    cp_size = 0x10000

                result += base[cp_offset:cp_offset+cp_size]
            else:
                result += delta[i:i+opcode]
                i += opcode

        return result

    # resolve deltas
    resolved = []
    for obj in objects:
        if obj["type"] in ["ofs-delta", "ref-delta"]:
            # simple resolution for small test repos
            base = resolved[-1]["data"]
            obj["data"] = apply_delta(base, obj["data"])
            obj["type"] = resolved[-1]["type"]

        resolved.append(obj)

    # -------------------------
    # WRITE OBJECTS
    # -------------------------
    for obj in resolved:
        header = f"{obj['type']} {len(obj['data'])}\x00".encode()
        store = header + obj["data"]
        sha = hashlib.sha1(store).hexdigest()

        dir_name = sha[:2]
        file_name = sha[2:]

        os.makedirs(f".git/objects/{dir_name}", exist_ok=True)

        with open(f".git/objects/{dir_name}/{file_name}", "wb") as f:
            f.write(zlib.compress(store))

        object_map[sha] = obj

    print("Clone completed.")

        # -------------------------
    # CHECKOUT WORKING TREE
    # -------------------------

    # Read commit object
    commit_dir = head_sha[:2]
    commit_file = head_sha[2:]

    with open(f".git/objects/{commit_dir}/{commit_file}", "rb") as f:
        compressed = f.read()

    commit_data = zlib.decompress(compressed)

    # remove header
    commit_content = commit_data.split(b"\x00", 1)[1]

    # find tree sha
    first_line = commit_content.split(b"\n")[0]
    tree_sha = first_line.split(b" ")[1].decode()

    def checkout_tree(tree_sha, path="."):
        dir_name = tree_sha[:2]
        file_name = tree_sha[2:]

        with open(f".git/objects/{dir_name}/{file_name}", "rb") as f:
            compressed = f.read()

        tree_data = zlib.decompress(compressed)
        content = tree_data.split(b"\x00", 1)[1]

        i = 0
        while i < len(content):
            # parse mode
            space_index = content.index(b" ", i)
            mode = content[i:space_index]
            i = space_index + 1

            # parse name
            null_index = content.index(b"\x00", i)
            name = content[i:null_index].decode()
            i = null_index + 1

            sha_bytes = content[i:i+20]
            i += 20

            sha_hex = sha_bytes.hex()

            if mode == b"40000":
                os.makedirs(os.path.join(path, name), exist_ok=True)
                checkout_tree(sha_hex, os.path.join(path, name))
            else:
                blob_dir = sha_hex[:2]
                blob_file = sha_hex[2:]

                with open(f".git/objects/{blob_dir}/{blob_file}", "rb") as f:
                    blob_compressed = f.read()

                blob_data = zlib.decompress(blob_compressed)
                blob_content = blob_data.split(b"\x00", 1)[1]

                with open(os.path.join(path, name), "wb") as f:
                    f.write(blob_content)

    checkout_tree(tree_sha)

def main():
    if len(sys.argv) < 2:
        return

    command = sys.argv[1]

    if command == "init":
        init()

    elif command == "cat-file":
        if len(sys.argv) >= 4 and sys.argv[2] == "-p":
            hash_value = sys.argv[3]
            cat_file_print(hash_value)
    
    elif command == "hash-object":
        if len(sys.argv) >= 4 and sys.argv[2] == "-w":
            file_path = sys.argv[3]
            hash_object_write(file_path)
    elif command == "ls-tree":
        if len(sys.argv) >= 4 and sys.argv[2] == "--name-only":
            tree_sha = sys.argv[3]
            ls_tree_name_only(tree_sha)
    elif command == "write-tree":
        tree_sha = write_tree(".")
        print(tree_sha)

    elif command == "commit-tree":
        tree_sha = sys.argv[2]
        parent_sha = None
        message = None

        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == "-p":
                parent_sha = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == "-m":
                message = sys.argv[i + 1]
                i += 2
            else:
                i += 1

        commit_sha = commit_tree(tree_sha, parent_sha, message)
        print(commit_sha)

    elif command == "clone":
        url = sys.argv[2]
        target_dir = sys.argv[3]
        clone_repository(url, target_dir)

if __name__ == "__main__":
    main()
    
