**1. Import Libraries:**

```python
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
```

**2. Load Dataset:**

```python
# Load the dataset
df = pd.read_csv('intrusion_detection.csv')

# Separate features and labels
X = df.drop('label', axis=1)
y = df['label']
```

**3. Data Preprocessing:**

```python
# Normalize the data
scaler = StandardScaler()
X = scaler.fit_transform(X)
```

**4. Model Training:**

```python
# Create a KNN classifier
classifier = KNeighborsClassifier()

# Train the model
classifier.fit(X, y)
```

**5. Intrusion Detection:**

```python
# Predict intrusion status for new data
new_data = # Input new data here
prediction = classifier.predict(new_data)

# Print the prediction
if prediction == 0:
    print('No intrusion detected.')
else:
    print('Intrusion detected.')
```

**Example Usage:**

```python
# Example new data
new_data = np.array([[100, 80, 150, 50],
                   [120, 90, 170, 60],
                   [150, 100, 200, 70]])

# Detect intrusions
for data in new_data:
    prediction = classifier.predict([data])
    if prediction == 0:
        print('No intrusion detected.')
    else:
        print('Intrusion detected.')
```

**Note:**

* Replace `intrusion_detection.csv` with the actual file name of your dataset.
* The `new_data` variable should contain the input data for which you want to detect intrusions.
* The accuracy of the intrusion detection system may vary depending on the dataset and model parameters.
