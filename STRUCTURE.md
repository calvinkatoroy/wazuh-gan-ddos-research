# Project Structure

```
wazuh-gan-ddos-research/
│
├── README.md                      # Main project documentation
├── TODO.md                        # Task list and project roadmap
├── config.yaml                    # Main configuration file
├── .gitignore                     # Git ignore rules
│
├── docs/                          # Documentation
│   ├── paper/                     # Research paper
│   │   ├── main.tex              # LaTeX main file
│   │   └── references.bib        # Bibliography
│   └── notes/                     # Research notes
│       ├── research_notes.md     # General research notes
│       ├── literature_review.md  # Literature review notes
│       └── meeting_notes.md      # Team meeting notes
│
├── src/                           # Source code
│   ├── gan/                       # GAN model implementation
│   │   ├── generator.py          # Generator network
│   │   ├── discriminator.py      # Discriminator network
│   │   └── train.py              # Training script
│   ├── preprocessing/             # Data preprocessing
│   │   ├── data_loader.py        # Data loading utilities
│   │   └── feature_extraction.py # Feature extraction
│   ├── analysis/                  # Analysis and evaluation
│   │   ├── evaluate.py           # Model evaluation
│   │   └── visualize.py          # Visualization tools
│   └── utils/                     # Utility functions
│       ├── logger.py             # Logging utilities
│       └── helpers.py            # Helper functions
│
├── config/                        # Configuration files
│   ├── wazuh/                     # Wazuh SIEM config
│   │   ├── ossec.conf            # Wazuh main configuration
│   │   └── rules.xml             # Custom detection rules
│   └── environment/               # Environment setup
│       ├── requirements.txt      # Python dependencies
│       └── environment.yml       # Conda environment
│
├── data/                          # Data directory
│   ├── raw/                       # Raw datasets
│   │   └── .gitkeep
│   ├── processed/                 # Processed datasets
│   │   └── .gitkeep
│   └── results/                   # Experiment results
│       └── .gitkeep
│
├── notebooks/                     # Jupyter notebooks
│   ├── 01_exploratory_analysis.ipynb
│   ├── 02_model_training.ipynb
│   └── 03_evaluation.ipynb
│
├── scripts/                       # Utility scripts
│   ├── setup_wazuh.sh            # Wazuh setup script
│   └── run_experiment.sh         # Experiment runner
│
└── tests/                         # Unit tests
    ├── test_gan.py               # GAN model tests
    └── test_preprocessing.py     # Preprocessing tests
```

## Directory Descriptions

### `/docs`
Contains all project documentation including the research paper (LaTeX), literature review notes, and meeting notes.

### `/src`
Main source code organized by functionality:
- **gan/**: GAN model architecture and training
- **preprocessing/**: Data loading and feature extraction
- **analysis/**: Model evaluation and visualization
- **utils/**: Common utility functions

### `/config`
Configuration files for:
- **wazuh/**: Wazuh SIEM settings and custom rules
- **environment/**: Python dependencies and conda environments

### `/data`
Data storage (git-ignored for large files):
- **raw/**: Original datasets (e.g., CIC-IDS2017, CICDDOS2019)
- **processed/**: Preprocessed and feature-extracted data
- **results/**: Experiment outputs, metrics, and model checkpoints

### `/notebooks`
Jupyter notebooks for exploratory analysis and experiments

### `/scripts`
Shell scripts for setup and automation

### `/tests`
Unit tests for code validation

## Getting Started

1. **Setup environment:**
   ```bash
   pip install -r config/environment/requirements.txt
   ```

2. **Configure Wazuh:**
   ```bash
   bash scripts/setup_wazuh.sh
   ```

3. **Download datasets:**
   Place datasets in `data/raw/`

4. **Run training:**
   ```bash
   python src/gan/train.py
   ```

5. **Evaluate model:**
   ```bash
   python src/analysis/evaluate.py
   ```

## Workflow

1. Literature review and documentation in `docs/notes/`
2. Data exploration in `notebooks/01_exploratory_analysis.ipynb`
3. Model development in `src/gan/`
4. Training and evaluation
5. Results analysis and visualization
6. Paper writing in `docs/paper/main.tex`
