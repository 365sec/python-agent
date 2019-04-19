


def aggregate_values(total, add):
    """
    Add the values in `add` to the total values in `total`.

    This function is called recursively to update subkeys.
    """
    for key, value in add.items():
        if isinstance(value, dict):
            if key not in total:
                total[key] = {}
            aggregate_values(total[key], value)
            continue

        if key in total:
            total[key] += value
        else:
            total[key] = value
