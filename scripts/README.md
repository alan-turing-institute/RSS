# Issue VC with `didkit`

## Requirements

For the script to run, you need to install [`didkit`](https://github.com/spruceid/didkit) and [`didkit-cli`](https://github.com/spruceid/didkit/tree/main/cli) first, by following the instructions in the respective `README` files. Install `didkit` in a new directory that is outside this `trustchain` repo.

## Script

After you've installed `didkit` and `didkit-cli`, move the script `issue-vc-didkit.sh` into the `didkit` repo. Within the repo `cli/tests/` should be a good location for the script. There are other scripts in that directory., like `example.sh` that this script was based on.

The shell script has two examples for issuing a VC with a UK home address, using `didkit-cli`. In example 1, the value of the `address` field is an object with several key value pairs (multi-line address). The value of the `address` field is one string containing the entire address in one line.

To run the script:
- Open a terminal and navigate to the root directory of the `didkit` repo.
- `cd cli/tests`
- Run `./issue-vc-didkit.sh`