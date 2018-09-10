#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ioprofiler Print time spent on vfs and block layer functions
#          For Linux, uses BCC, eBPF.
#
# USAGE:  ioprofiler.py [-h] [-p PID] [-s {all,vfs,bio,plug,blk}] [interval]
#

from __future__ import print_function
import time
import argparse
from bcc import BPF


parser = argparse.ArgumentParser(
    description="IO Profiler: Print time spent on vfs and block layer functions",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
                    help="output interval, in seconds")
parser.add_argument("-s", "--show", default="all",
                    choices=["all", "vfs", "bio", "plug", "blk"],
                    help="show specific operation, default all")
args = parser.parse_args()
interval = int(args.interval)

# load BPF program
bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>


#define VFS_OP 1
#define BIO_OP 2
#define PLUG_OP 3
#define BLK_OP 4

BPF_PERF_OUTPUT(events);

// for saving process info by request
struct who_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};


// the key for the output summary
struct info_t {
    u32 pid;
    int rwflag;
    int major;
    int minor;
    char name[TASK_COMM_LEN];
    u64 delta;
    u64 sector;
    u64 len;
    char disk_name[DISK_NAME_LEN];
    char msg[64];
    char fn[64];
    int flag;
};

// the value of the output summary
struct val_t {
    u64 bytes;
    u64 us;
    u32 io;
};

BPF_HASH(start, struct request *);
BPF_HASH(whobyreq, struct request *, struct who_t);
BPF_HASH(counts, struct info_t, struct val_t);
BPF_HASH(submitbio, struct bio *);
BPF_HASH(plugtime, struct blk_plug *);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER

    struct who_t who = {};
    if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0) {
        who.pid = bpf_get_current_pid_tgid();
        whobyreq.update(&req, &who);
    }

    return 0;
}

int trace_blk_fetch_request(struct pt_regs *ctx, struct request *req) {
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    char msg[]="fetch a req from a request queue";

    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER

    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}
// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER

    u64 *tsp;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;    // missed tracing issue
    }

    struct who_t *whop;
    struct val_t *valp, zero = {};
    u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // setup info_t key
    struct info_t info = {}; 
    info.flag = BLK_OP;
    info.major = req->rq_disk->major;
    info.minor = req->rq_disk->first_minor;
    info.len = req->__data_len;
    info.sector = req->__sector;
    struct gendisk *rq_disk = req->rq_disk;
    bpf_probe_read(&info.disk_name, sizeof(info.disk_name),
                       rq_disk->disk_name);

    char msg[]="blk account io completion";
    bpf_probe_read_str(&info.msg, sizeof(msg), msg);

    whop = whobyreq.lookup(&req);
    if (whop == 0) {
        // missed pid who, save stats as pid 0
        valp = counts.lookup_or_init(&info, &zero);
    } else {
        info.pid = whop->pid;
        __builtin_memcpy(&info.name, whop->name, sizeof(info.name));
        valp = counts.lookup_or_init(&info, &zero);
    }

    // save stats
    valp->us += delta_us;
    valp->bytes += req->__data_len;
    valp->io++;

    start.delete(&req);
    whobyreq.delete(&req);

    events.perf_submit(ctx, &info, sizeof(struct info_t));
    return 0;

}

// write
int trace_write_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER 

    char msg[]=" vfs write ";
    // Setup filename
    struct info_t info = {};
    info.flag = VFS_OP;
    info.major = 0;
    info.minor = 0;
    info.pid = pid;
    bpf_get_current_comm(&info.name, sizeof(info.name));
    bpf_probe_read_str(&info.msg, sizeof(msg), msg);

    char fn[64] = {0};
    struct qstr d_name = file->f_path.dentry->d_name;
    bpf_probe_read(&fn, sizeof(fn),(void *)d_name.name);
    bpf_probe_read_str(&info.fn, sizeof(fn), fn);

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_init(&info, &zero);
    valp->us += 0;
    valp->bytes += count;
    valp->io++;

    events.perf_submit(ctx, &info, sizeof(struct info_t));
    return 0;
}

// read
int trace_read_entry(struct pt_regs *ctx, struct file *file,
    char __user *buf, size_t count)
{
    u32 pid = bpf_get_current_pid_tgid();

    FILTER 

    char msg[]=" vfs read";
    // Setup filename
    struct info_t info = {};
    info.flag = VFS_OP;
    info.major = 0;
    info.minor = 0;
    info.pid = pid;
    bpf_get_current_comm(&info.name, sizeof(info.name));
    bpf_probe_read_str(&info.msg, sizeof(msg), msg);

    char fn[64] = {0};
    struct qstr d_name = file->f_path.dentry->d_name;
    bpf_probe_read(&fn, sizeof(fn),(void *)d_name.name);
    bpf_probe_read_str(&info.fn, sizeof(fn), fn);

    struct val_t *valp, zero = {};
    valp = counts.lookup_or_init(&info, &zero);
    valp->us += 0;
    valp->bytes += count;
    valp->io++;

    events.perf_submit(ctx, &info, sizeof(struct info_t));
    return 0;
}

int trace_blk_finish_plug(struct pt_regs *ctx, struct blk_plug *plug) {
    u32 pid = bpf_get_current_pid_tgid();

    FILTER
    struct info_t info = {};
    info.flag = PLUG_OP;
    info.major = 0;
    info.minor = 0;
    info.pid = pid;
    bpf_get_current_comm(&info.name, sizeof(info.name));

    u64 *tsp;

    tsp = plugtime.lookup(&plug);
    if (tsp != 0) {
        char msg[]="plug finished.";
        bpf_probe_read_str(&info.msg, sizeof(msg), msg);

        struct val_t *valp, zero = {};
        valp = counts.lookup_or_init(&info, &zero);
        u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
        valp->us = delta_us;

        events.perf_submit(ctx, &info, sizeof(struct info_t));
        plugtime.delete(&plug);
    }
    return 0;
}

int trace_blk_start_plug(struct pt_regs *ctx, struct blk_plug *plug) {
    u32 pid = bpf_get_current_pid_tgid();

    FILTER

    u64 ts;

    ts = bpf_ktime_get_ns();
    plugtime.update(&plug, &ts);

    return 0;
}

int trace_submit_bio(struct pt_regs *ctx, struct bio *bio) {
    u32 pid = bpf_get_current_pid_tgid();

    FILTER 

    u64 ts;
    char msg2[32]={0};
    ts = bpf_ktime_get_ns();
    submitbio.update(&bio, &ts);

    return 0;
}

int trace_bio_endio(struct pt_regs *ctx, struct bio *bio) {
    u32 pid = bpf_get_current_pid_tgid();

    FILTER 

    struct info_t info = {};
    info.flag = BIO_OP;
    info.major = 0;
    info.minor = 0;
    info.pid = pid;
    bpf_get_current_comm(&info.name, sizeof(info.name));

    u64 *tsp;

    tsp = submitbio.lookup(&bio);
    if (tsp != 0) {
        char msg[]="bio finished";
        bpf_probe_read_str(&info.msg, sizeof(msg), msg);

        struct val_t *valp, zero = {};
        valp = counts.lookup_or_init(&info, &zero);
        u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
        valp->us= delta_us;

        events.perf_submit(ctx, &info, sizeof(struct info_t));
        submitbio.delete(&bio);
    }
    return 0;
}


"""
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
                                'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')

# initialize BPF
b = BPF(text=bpf_text)

b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")
b.attach_kprobe(event="bio_endio", fn_name="trace_bio_endio")

b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_completion",
                fn_name="trace_req_completion")

b.attach_kprobe(event="blk_start_plug", fn_name="trace_blk_start_plug")
b.attach_kprobe(event="blk_finish_plug", fn_name="trace_blk_finish_plug")
b.attach_kprobe(event="blk_fetch_request", fn_name="trace_blk_fetch_request")

print('Tracing... Output every %d secs, Hit Ctrl-C to end' % interval)
# header

if args.show == "blk" or args.show == "all":
    print("%-6s %-16s %1s %-3s %-3s %-8s %5s %7s %-16s %-16s %-5s %6s" % ("PID", "COMM",
                                                                          "D", "MAJ", "MIN",
                                                                          "DISK", "I/O", "Kbytes",
                                                                          "Sector", "Len", "MSG",
                                                                          "AVGms"))
elif args.show == "bio" or args.show == "plug":
    print("%-6s %-16s %-32s %-6s " % ("PID", "COMM", args.show.upper() + "_OP", "TIMEns"))
elif args.show == "vfs":
    print("%-6s %-16s %-32s %-10s %6s " % ("PID", "COMM", "VFS_OP", "FILENAME", "AVGms"))

# process event
VFS_OP = 1
BIO_OP = 2
PLUG_OP = 3
BLK_OP = 4


def print_event(cpu, data, size):
    try:
        time.sleep(interval)
        counts = b.get_table("counts")
        for k, v in counts.items():
            # print line
            if k.flag == BIO_OP and (args.show == "all" or args.show == "bio"):
                print("%-6d %-16s %-32s  %6s " % (k.pid, k.name.decode(), k.msg, v.us))
            elif k.flag == PLUG_OP and (args.show == "all" or args.show == "plug"):
                print("%-6d %-16s %-32s  %6s " % (k.pid, k.name.decode(), k.msg, v.us))
            elif k.flag == VFS_OP and (args.show == "all" or args.show == "vfs"):
                avg_ms = (float(v.us) / 1000) / v.io
                print("%-6d %-16s %-32s %-10s %6.2f" % (k.pid, k.name.decode(), k.msg, k.fn, avg_ms))
            elif k.flag == BLK_OP and (args.show == "all" or args.show == "blk"):
                avg_ms = (float(v.us) / 1000) / v.io
                print("%-6d %-16s %1s %-3d %-3d %-5s %2s %3s %16s %10s %5s %6.2f" % (k.pid,
                                                                                     k.name.decode(),
                                                                                     "W" if k.rwflag else "R",
                                                                                     k.major, k.minor,
                                                                                     k.disk_name, v.io, v.bytes / 1024,
                                                                                     k.sector, k.len, k.msg, avg_ms))
        counts.clear()
    except KeyboardInterrupt:
        print("Detaching...")
        exit()


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()

