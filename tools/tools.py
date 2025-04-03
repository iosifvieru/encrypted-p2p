from BigNumber.BigNumber import BigNumber

# my_pow - implements the pow algorithm for big numbers
def my_pow(m: int, e: int, n: int) -> int:
    first_extra_factor = None
    second_extra_factor = None

    while e != 1:
        if e % 2 == 1:
            if first_extra_factor is None:
                first_extra_factor = m
            else:
                second_extra_factor = m

        m = (m ** 2) % n
        e = e // 2

        if first_extra_factor is not None and second_extra_factor is not None:
            first_extra_factor = (first_extra_factor * second_extra_factor) % n
            second_extra_factor = None

    if first_extra_factor is None:
        first_extra_factor = 1

    return (m * first_extra_factor) % n


