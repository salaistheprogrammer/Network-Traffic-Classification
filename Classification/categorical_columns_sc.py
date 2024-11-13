import pandas as pd
from ext_features_preprocess import extract_features, preprocess


def select_categorical_columns(df: pd.DataFrame) -> list:

    possible_categorical = df.select_dtypes(include=['object', 'category']).columns
    
    categorical_columns = []
    for col in possible_categorical:
        if not pd.api.types.is_numeric_dtype(df[col]):
            sample_value = df[col].dropna().iloc[0] 
            if not sample_value.isdigit():  # Exclude columns with purely numeric values
                categorical_columns.append(col)
    categorical_columns.remove('Label') if 'Label' in categorical_columns else None

    return categorical_columns

# Assuming df is your DataFrame
# categorical_columns = select_categorical_columns(df)

# print("Categorical columns:", categorical_columns)