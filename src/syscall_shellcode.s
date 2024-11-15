.text
.global perform_syscall
.type perform_syscall,@function

perform_syscall:
    MOV             X8, X0
    MOV             X0, X1
    MOV             X1, X2
    MOV             X2, X3
    MOV             X3, X4
    MOV             X4, X5
    MOV             X5, X6
    SVC             0
    RET