'''
Metadata-Version: 1.2
Name: floss2yar
Version: 0.1
Summary: Generate YARA Rules Based on FLOSS Finding Decoding Functions
Home-page: UNKNOWN
Author: Greg Lesnewich & Connor McLaughlin
Author-email: glesnewich@gmail.com
License: UNKNOWN
Description: UNKNOWN
Platform: UNKNOWN
Requires-Python: >=3.6
'''

import argparse
import os

from yar_utils import func_parsing
from yar_utils import processing


def run_floss(filepath, score, name):
  extracted = func_parsing.floss_func_parsing(filepath, score)
  processing.data_processing(extracted, name)

def main():
  parser = argparse.ArgumentParser(description="Create a masked YARA rule for a file based on FLOSS finding likely decoding functions")
  parser.add_argument("-f", "--file", help="Specify file to parse", metavar="<file>", required=True)
  parser.add_argument("-s", "--score", help="Minumum FLOSS Func Scoring Threshold to Create YARA Rules from (default: 0.90)", metavar="<threshold_score>", required=False)
  parser.add_argument("-n", "--name", help="Name for output rules - example MAL_EVILDOOR without quotes", metavar="<output_rule_names>", required=False)
  args = parser.parse_args()

  if args.file:
    try:
      run_floss(args.file, args.score, args.name)
    except:
      print("finding decode funcs failed")


if __name__ == "__main__":
    main()

