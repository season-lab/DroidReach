import re

def manip_grep_c(lines,filename):
    #print(f"Processing {filename}")
    res = {}
    for line in lines:
        apk_hash, num = line.strip().split(":")
        res[apk_hash] = num
    return res


base_path = "NEW_cugurra_dr_logs/"

def print_dir_contents(mypath):
    from os import listdir
    from os.path import isfile, join
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    return onlyfiles

all_logs = print_dir_contents(base_path)

columns = [manip_grep_c(open(base_path+log).readlines(),base_path+log) for log in all_logs]


def sdl(d,key): #safe dict lookup
    if key not in d:
        return 0
    else:
        return d[key]
    
def calc_time_spent(ts_dict:dict):
    apps = ts_dict.keys()
    rev_lookup = {}
    ts = []
    for k in apps:
        v = ts_dict[k]
        ts.append(v)
        rev_lookup[v] = k
    ts.sort()
    time_spent = {}
    first_app = rev_lookup[ts[0]]
    time_spent[first_app] = 0
    for i in range(1, len(ts)):
        start,end = ts[i-1], ts[i]
        app = rev_lookup[end]
        time_spent[app] = int(end) - int(start)
    return time_spent


# Generate processing time from timestamp delta
all_logs = [l[:-4] for l in all_logs]
all_logs.append("time_spent")

timestamp_dict = columns[all_logs.index("last_timestamp")]
columns.append(calc_time_spent(timestamp_dict))

all_apps = timestamp_dict.keys()

# Print CSV
print("apk," + ','.join(all_logs))
for apk in all_apps:
    cells = [str(sdl(c,apk)) for c in columns]
    row = apk + "," + ",".join(cells)
    print(row)

