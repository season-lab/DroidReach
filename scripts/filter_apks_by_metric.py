import pandas as pd

FILENAME = "./full_cugurra.csv"

def strip_suffix(s):
    return s.split(".")[0]

# List just by Hash
df = pd.read_csv(FILENAME,encoding="utf16")
df["apk"] = df["apk"].apply(strip_suffix)
# Add app name information
names = pd.read_csv("./dataset.csv")
names = names.rename(columns={"hash (sha256)": "apk"})
df = pd.merge(df, names, "left")
print(df)


# Example subset: only apks with one consumer.
# Build text files to perform deeper tests on certain subsets!
# confirmed_consumer = df[df["consumers_found"] > 0]
# confirmed_consumer.to_csv("./filtered_cugurra_consumers.csv", sep=",")

# sorted_cc = confirmed_consumer.sort_values(by="consumers_found",ascending=False)
# print(sorted_cc)

order = ["completed_execution","methods_explored","consumers_found","jlong_but_not_consumers","total_not_consumers","num_producer_pairs","full_runs_producers","errors","warnings","last_timestamp","time_spent"]
ordered = df[order]
ordered.to_csv("full_cugurra_ordered.csv")