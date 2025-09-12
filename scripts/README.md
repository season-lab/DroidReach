# Helper Scripts

## Batch Experiments

Given an APK dataset in a tar archive, extract them one at a time and test all reachable methods for consumer-producer relationships.
Keep in mind this type of testing will produce a number of false negatives when DroidReach gets stuck mid-analysis.
You will also have to manually kill the Python process of the current sample.

Customize your DroidReach installation location in the scripts and run `run_batch.sh archive_location.tar` to test the entire dataset. 
Alternatively, operate only on a subset by specifying the samples in a separate `subset.txt` file and run  `run_subset.sh archive_location.tar` instead.

To run similar tests on the existing benchmarks, check out `run_benchmark.sh`. 
Keep in mind none of the existing benchmarks use this pattern. It can be a good base for your own experiments on them.
It also includes a better timestamp feature to be ported soon into the other scripts.

For the tar archive structure, I would recommend your samples are nested at least one level. 
This is because these scripts will log the individual APK results in `log_$APK`. 
For instance, if your samples are nested inside an `apk_dataset` folder, your text logs will be saved inside `~/log_apk_dataset/[sha256 hash of each apk]`.
You will need to create this base folder.
This will also make it much easier to operate on the next steps.

## Data Manipulation

If you've organized the text logs as mentioned before, I have included a number of scripts which will make it easier to extrapolate numerical results.

`collect_logs.sh` will count the occurrences of certain events in each text log. This includes extracting information about consumers, producers, errors, and such.
Once they are collected, all metrics are grouped and compressed into a tar archive.

`generate_csv_single.py` will take the unzipped folder and create a CSV with all data consolidated by APK name. 
This can be easily imported into any spreadsheet for manual analysis, or it can be further manipulated by other scripts.

You can merge multiple build data from the same dataset, filter or reorder each column programmatically, or extract information for further tests, ie. for generating a `subset.txt` file automatically.

`filter_apks_by_metric.py` contains a couple examples of this. First, it re-associates app package names to their hashes. Then, it creates a separate CSV for apps with at least one confirmed consumer and orders the samples by number of consumers. Finally, it reorders the columns in the original CSV to be more relevantly associated next to each other in the final CSV.