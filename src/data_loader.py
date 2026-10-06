import pandas as pd

from src.validators import validate_threat_data


DATA_FILE = "data/threat_intelligence.csv"


def load_threat_data():
    """
    Load and validate the threat intelligence dataset.

    Returns:
        pandas.DataFrame: Validated threat intelligence data.

    Raises:
        ValueError: If validation errors are found.
    """

    try:
        df = pd.read_csv(DATA_FILE)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Threat intelligence dataset not found: {DATA_FILE}"
        )

    # Remove accidental spaces from column names
    df.columns = df.columns.str.strip()

    # Validate dataset
    errors = validate_threat_data(df)

    if errors:
        error_message = "\n".join(
            f"- {error}" for error in errors
        )

        raise ValueError(
            f"Threat intelligence data validation failed:\n{error_message}"
        )

    # Convert date column
    df["observed_date"] = pd.to_datetime(
        df["observed_date"],
        errors="coerce"
    )

    # Sort newest observations first
    df = df.sort_values(
        by="observed_date",
        ascending=False
    ).reset_index(drop=True)

    return df