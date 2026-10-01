#define _GNU_SOURCE
#include "btfcheck.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BTF_MAGIC 0xeb9f
#define BTF_KIND_STRUCT 4
#define BTF_KIND_UNION 5
#define BTF_INFO_KIND(i) (((i) >> 24) & 0x1f)
#define BTF_INFO_VLEN(i) ((i) & 0xffff)
#define BTF_INFO_KFLAG(i) ((i) >> 31)

struct btf_header_local {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;
    uint32_t type_off;
    uint32_t type_len;
    uint32_t str_off;
    uint32_t str_len;
};

struct btf_type_local {
    uint32_t name_off;
    uint32_t info;
    uint32_t size;
};

struct btf_member_local {
    uint32_t name_off;
    uint32_t type;
    uint32_t offset;
};

struct need_member {
    const char *structure;
    const char *member;
    int found;
    uint32_t byte_offset;
};

static struct need_member needs[] = {
    { "cred", "uid", 0, 0 },
    { "cred", "user_ns", 0, 0 },
    { "user_namespace", "parent", 0, 0 },
    { "task_struct", "cred", 0, 0 },
    { "page", "_refcount", 0, 0 },
    { "skb_shared_info", "nr_frags", 0, 0 },
    { "skb_shared_info", "frags", 0, 0 },
};

static int valid_string(const char *strings, size_t length, uint32_t off)
{
    return off < length && memchr(strings + off, '\0', length - off) != NULL;
}

int btf_check_required(const char *path, int verbose)
{
    struct stat st;
    unsigned char *blob = NULL;
    const struct btf_header_local *hdr;
    const unsigned char *types, *types_end;
    const char *strings;
    size_t strings_len;
    int fd = -1, rc = -1;

    for (size_t i = 0; i < sizeof(needs) / sizeof(needs[0]); i++)
        needs[i].found = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[-] BTF: cannot open %s: %s\n", path, strerror(errno));
        goto out;
    }
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(*hdr) ||
        st.st_size > 128 * 1024 * 1024) {
        fprintf(stderr, "[-] BTF: invalid file size\n");
        goto out;
    }
    blob = (unsigned char *)malloc((size_t)st.st_size);
    if (!blob) {
        fprintf(stderr, "[-] BTF: allocation failed\n");
        goto out;
    }
    for (size_t done = 0; done < (size_t)st.st_size;) {
        ssize_t n = read(fd, blob + done, (size_t)st.st_size - done);
        if (n <= 0) {
            fprintf(stderr, "[-] BTF: short read\n");
            goto out;
        }
        done += (size_t)n;
    }

    hdr = (const struct btf_header_local *)blob;
    if (hdr->magic != BTF_MAGIC || hdr->version != 1 ||
        hdr->hdr_len < sizeof(*hdr) || hdr->hdr_len > (uint32_t)st.st_size) {
        fprintf(stderr, "[-] BTF: bad header (magic/version/length)\n");
        goto out;
    }
    if ((uint64_t)hdr->hdr_len + hdr->type_off + hdr->type_len > (uint64_t)st.st_size ||
        (uint64_t)hdr->hdr_len + hdr->str_off + hdr->str_len > (uint64_t)st.st_size) {
        fprintf(stderr, "[-] BTF: section outside file\n");
        goto out;
    }
    types = blob + hdr->hdr_len + hdr->type_off;
    types_end = types + hdr->type_len;
    strings = (const char *)(blob + hdr->hdr_len + hdr->str_off);
    strings_len = hdr->str_len;

    while (types < types_end) {
        const struct btf_type_local *t;
        const struct btf_member_local *members;
        uint32_t kind, vlen;
        size_t extra = 0;

        if ((size_t)(types_end - types) < sizeof(*t)) {
            fprintf(stderr, "[-] BTF: truncated type record\n");
            goto out;
        }
        t = (const struct btf_type_local *)types;
        kind = BTF_INFO_KIND(t->info);
        vlen = BTF_INFO_VLEN(t->info);

        switch (kind) {
        case 1: extra = 4; break;                    /* INT */
        case 3: extra = 12; break;                   /* ARRAY */
        case 4: case 5: extra = (size_t)vlen * 12; break;
        case 6: extra = (size_t)vlen * 8; break;     /* ENUM */
        case 13: extra = (size_t)vlen * 8; break;    /* FUNC_PROTO */
        case 14: extra = 4; break;                   /* VAR */
        case 15: extra = (size_t)vlen * 12; break;   /* DATASEC */
        case 17: extra = 4; break;                   /* DECL_TAG */
        case 19: extra = (size_t)vlen * 12; break;   /* ENUM64 */
        default: extra = 0; break;
        }
        if (extra > (size_t)(types_end - types - sizeof(*t))) {
            fprintf(stderr, "[-] BTF: malformed type payload\n");
            goto out;
        }

        if ((kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) &&
            valid_string(strings, strings_len, t->name_off)) {
            const char *sname = strings + t->name_off;
            members = (const struct btf_member_local *)(t + 1);
            for (size_t i = 0; i < sizeof(needs) / sizeof(needs[0]); i++) {
                if (strcmp(sname, needs[i].structure) != 0)
                    continue;
                for (uint32_t j = 0; j < vlen; j++) {
                    uint32_t bitoff = BTF_INFO_KFLAG(t->info) ?
                        (members[j].offset & 0x00ffffffU) : members[j].offset;
                    if (valid_string(strings, strings_len, members[j].name_off) &&
                        strcmp(strings + members[j].name_off, needs[i].member) == 0) {
                        needs[i].found = 1;
                        needs[i].byte_offset = bitoff / 8;
                    }
                }
            }
            if (strcmp(sname, "skb_shared_info") == 0 && t->size != 320) {
                fprintf(stderr, "[-] BTF: sizeof(skb_shared_info)=%u, expected 320\n", t->size);
                goto out;
            }
        }
        types += sizeof(*t) + extra;
    }

    for (size_t i = 0; i < sizeof(needs) / sizeof(needs[0]); i++) {
        if (!needs[i].found) {
            fprintf(stderr, "[-] BTF: missing struct %s.%s\n",
                    needs[i].structure, needs[i].member);
            goto out;
        }
        if (verbose)
            fprintf(stderr, "[+] BTF: struct %s.%s @ +0x%x\n",
                    needs[i].structure, needs[i].member, needs[i].byte_offset);
    }
    if (needs[5].byte_offset != 2 || needs[6].byte_offset != 0x30) {
        fprintf(stderr, "[-] BTF: skb_shared_info geometry differs: nr_frags=0x%x frags=0x%x\n",
                needs[5].byte_offset, needs[6].byte_offset);
        goto out;
    }

    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    free(blob);
    return rc;
}
