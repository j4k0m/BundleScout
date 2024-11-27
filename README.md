# BundleScout
A tool designed to extract and analyze React Native bundles from Android APK files. It provides insights into the structure and content of the JavaScript code within the APK, identifying API endpoints, potential secrets, and other relevant information. 

## Features

- Extracts React Native bundles from APK files.
- Analyzes JavaScript files for API endpoints and potential secrets.
- Provides insights into the bundle structure, including modules and dependencies.
- Supports saving analysis results to a JSON file.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/j4k0m/BundleScout.git
cd BundleScout
```

2. Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage:

To analyze an APK file, run the following command:

```bash
python scout.py <path_to_apk> [--save-json] [--output-dir <output_directory>]
```

- `<path_to_apk>`: Path to the APK file you want to analyze.
- `--save-json`: Optional flag to save the analysis results to a JSON file.
- `--output-dir`: Optional directory to save the extracted bundle and analysis results.

## License:

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contributing:

Contributions are welcome! Please feel free to submit a pull request or open an issue.
