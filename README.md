# AdBlock Filter Compiler

This repository offers a Python script that combines and processes various blocklists, host files, and domain lists to produce an AdBlock filter list. A sorted list of domains in AdBlock syntax format is produced after the script eliminates duplicates.

## Features

- Combines multiple blocklists, host files, and domain lists into a single AdBlock filter list
- Removes duplicate entries
- Generates a header with the date, domain count, and the number of duplicates removed
- Optional: similar functionality whitelist.txt

## Included Filter Lists

I like to leave the actual hard work to the professionals, like the ones below, who compile complete lists for us.  This work gathers completed lists, and organizes it into one neat file removing duplicates to get the cleanest, uniform, smallest possible file from all the lists you may want to use.

This project combines the following filter lists by default:

You can easily add your own blacklists or whitelists by modifying the `config.json` script and updating the `blacklist_urls` or `whitelist_urls` section with the URLs of your custom filter lists.

This project uses my own personal whitelist by default:
- [Kin9Loui3 Whitelist]()

## Usage

1. Clone the repository or download the source code.
2. Add or remove URLs in the `config.json` file to your liking.
4. Run the `adblock_filter_compiler.py` script. This will generate the .txt file(s) with the combined filter list in AdBlock syntax format. Ready for import.

## Automated Updates

This repository uses GitHub Actions to automate the filter generation process. The workflow runs every day and updates the `blacklist.txt` and `whitelist.txt` file if there are any changes.

## Dependencies

- Python 3.x
- requests

## Contributing

Feel free to open an issue or submit a pull request if you have any improvements or suggestions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
