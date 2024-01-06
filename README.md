# Python Code Examples in Rust-Powered Sandbox API

Explore how Python code executes in a Rust-powered API environment with these illustrative examples.

## Example 1: Calculating the Hypotenuse

Calculate the hypotenuse of a right-angled triangle.

### Raw Body
```python
import math

a = 3 
b = 4

hypotenuse = math.sqrt(a**2 + b**2)
hypotenuse
```

### JSON Result
```json
{
	"result": "5.0"
}
```
*The result "5.0" represents the hypotenuse length of a triangle with sides 3 and 4.*

## Example 2: Working with SQLite Database

Creating and querying an in-memory SQLite database.

### Raw Body
```python
import sqlite3

conn = sqlite3.connect(':memory:')

cursor = conn.cursor()

cursor.execute('''CREATE TABLE pessoas (nome TEXT)''')

nomes = [('Paul',), ('Eric',), ('Jesus',)]
cursor.executemany('INSERT INTO persons VALUES (?)', nomes)

conn.commit()

cursor.execute('SELECT * FROM persons')
rows = cursor.fetchall()

conn.close()

rows
```

### JSON Result
```json
{
	"result": "[('Paul',), ('Eric',), ('Jesus',)]"
}
```
*This result shows the names inserted into the 'persons' table, demonstrating the use of SQLite in Python.*

