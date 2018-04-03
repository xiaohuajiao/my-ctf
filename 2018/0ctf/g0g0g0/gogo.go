package main

import (
	"fmt"
)

// max
func func0(a, b int) int {
    if a > b {
        return a
    } else {
        return b
    }
}


// cmp
func func1(aa, bb []int) (int) {
    var a, b []int

    for i := len(aa) - 1; i >= 0; i-- {
        if aa[i] > 0 {
            a = aa[:i+1]
            break
        }
    }
    for i := len(bb) - 1; i >= 0; i-- {
        if bb[i] > 0 {
            b = bb[:i+1]
            break
        }
    }

    if len(a) > len(b) {
        return 1
    } else if (len(a) < len(b)) {
        return -1
    } else {
        for i := len(a) - 1; i >= 0; i-- {
            if a[i] > b[i] {
                return 1
            } else if a[i] < b[i] {
                return -1
            }
        }
    }
    return -2
}

// add
func func2(a, b []int) ([]int) {
    size := func0(len(a), len(b))+1
    c := make([]int, size)

    carry := 0
    for i, _ := range c {
        a_i := 0
        b_i := 0
        if i < len(a) {
            a_i = a[i]
        }
        if i < len(b) {
            b_i = b[i]
        }

        tmp := a_i + b_i + carry
        carry = tmp / 10
        if tmp >= 10 {
            tmp %= 10
        }
        c[i] = tmp
    }
    return c
}


// sub
func func3(a, b []int) ([]int) {
    if (func1(a, b) == -1) {
        return []int{}
    }
    c := make([]int, len(a))

    for i := 0; i < len(a); i++ {
        a_i := 0
        b_i := 0
        if i < len(a) {
            a_i = a[i]
        }
        if i < len(b) {
            b_i = b[i]
        }

        if a_i < b_i {
            a[i+1] -= 1
            a_i += 10
        }
        c[i] = a_i - b_i
    }
    return c
}

// mul
func func4(a, b []int) ([]int) {
    c := make([]int, len(a) + len(b))

    for i, _ := range c {
        c[i] = 0
    }

    var tmp int;

    for i := 0; i < len(b); i++ {
        for j := 0; j < len(a); j++ {
            tmp = a[j] * b[i]
            c[i+j] += tmp
            /*
            if c[i+j] >= 10 {
                c[i+j+1] += c[i+j] / 10;
                c[i+j] %= 10
            }
            */
        }
    }

    for i, _ := range c[:len(c)-1] {
        if c[i] >= 10 {
            c[i+1] += c[i] / 10
            c[i] %= 10
        }
    }
    return c
}

// div
func func5(a, b []int) ([]int) {
    return []int{}
}

// stringToIntArray
func func6(a string) ([]int) {
    rst := make([]int, 0, len(a))

    for i := len(a)-1; i >= 0; i-- {
        tmp := int(a[i] - '0')
        if tmp >= 0 && tmp < 10 {
            rst = append(rst, tmp)
        }
    }

    return rst
}

// outputInt
func func7(a []int) {
    skip := true
    for i := len(a)-1; i >= 0; i-- {
        if skip && a[i] > 0 {
            skip = false
        }
        if !skip {
            fmt.Printf("%d", a[i])
        }
    }

    if skip {
        fmt.Printf("0")
    }
    fmt.Println("");
}

func main() {
    flag := "flag{Welcome_to_0CTF_2018!gogogo}"

    /*
    a := func6("4373612677928697257861252602371390152816537558161613618621437993378423467772036")
    b := func6("36875131794129999827197811565225474825492979968971970996283137471637224634055579")
    c := func6("154476802108746166441951315019919837485664325669565431700026634898253202035277999")
    */

    var sa, sb, sc string;

    fmt.Println("Input 3 numbers")
    fmt.Scanf("%s", &sa)
    fmt.Scanf("%s", &sb)
    fmt.Scanf("%s", &sc)

    a := func6(sa)
    b := func6(sb)
    c := func6(sc)

    if len(a) == 0 || len(b) == 0 || len(c) == 0 {
        fmt.Println("Invalid input")
        return
    }

    // fmt.Printf("%v %v %v", a, b, c)
    if func1(a, []int{0}) <= 0 ||
        func1(b, []int{0}) <= 0 ||
        func1(c, []int{0}) <= 0 {
        fmt.Println("Only Positive integer")
        return
    }

    s1 := func2(a, b)
    s2 := func2(a, c)
    s3 := func2(b, c)

    t1 := func4(func4(s1, s2), a)
    t2 := func4(func4(s1, s3), b)
    t3 := func4(func4(s2, s3), c)

    /*
    fmt.Println("s1: "); func7(s1)
    fmt.Println("s2: "); func7(s2)
    fmt.Println("s3: "); func7(s3)
    fmt.Println("t1: "); func7(t1)
    fmt.Println("t2: "); func7(t2)
    fmt.Println("t3: "); func7(t3)
    */

    r1 := func2(t1, func2(t2, t3))

    c4 := []int{10}
    r2 := func4(c4, func4(s1, func4(s2, s3)))

    if func1(r1, r2) == 0 {
        fmt.Printf("Correct! flag is %s\n", flag)
    } else {
        fmt.Println("Wrong! Try again!!")
    }
}
