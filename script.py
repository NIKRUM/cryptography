import re
from collections import defaultdict

# Ścieżka do pliku
filename = "DES_F.txt"
# Próg P-value dla uznania testu za "zdany"
threshold = 0.01
# Licznik wszystkich testów
total_tests = 0
# Licznik udanych testów
successful_tests = 0

# Wczytaj plik linia po linii
with open(filename, 'r', encoding='utf-8') as file:
    for line in file:
        parts = line.strip().split()
        if len(parts) >= 3:
            p_value_str = parts[-3]
            test_name = parts[-1]
            if test_name.isalpha():
                total_tests += 1  # Zliczamy każdy wiersz z nazwą testu

                if p_value_str != "----":
                    try:
                        p_value = float(p_value_str)
                        if 0 < p_value <= 1.0 and p_value >= threshold:
                            successful_tests += 1
                    except ValueError:
                        continue

# Oblicz wartość R
R = (successful_tests / total_tests) * 100 if total_tests > 0 else 0

# Słownik do przechowywania wartości P dla każdego testu (do wyświetlenia średnich)
p_values_by_test = defaultdict(list)
with open(filename, 'r', encoding='utf-8') as file:
    for line in file:
        parts = line.strip().split()
        if len(parts) >= 3:
            p_value_str = parts[-3]
            test_name = parts[-1]
            if test_name.isalpha() and p_value_str != "----":
                try:
                    p_value = float(p_value_str)
                    if 0 < p_value <= 1.0:
                        p_values_by_test[test_name].append(p_value)
                except ValueError:
                    continue

# Oblicz średnie P-value (opcjonalne, do wyświetlenia)
average_p_values = {
    test: sum(values) / len(values)
    for test, values in p_values_by_test.items()
    if values
}

# Wyświetl wyniki
print("Średnie wartości P-value dla testów:\n")
for test, avg in average_p_values.items():
    print(f"{test}: {avg:.4f}")
print(f"\nWartość R (procent udanych testów do wszystkich przeprowadzonych): {R:.2f}%")