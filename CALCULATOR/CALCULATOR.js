let display = document.getElementById("display");
let buttons = document.querySelectorAll("button");
let input = "";

buttons.forEach(button => {
    button.addEventListener("click", () => {
        if (button.id === "clear") {
            input = "";
            display.value = "";
        }
        else if (button.id === "equals") {
            try {
                input = eval(input);
                display.value = input;
            } catch {
                display.value = "Error";
                input = "";
            }
        }
        else if (button.id === "square") {
            if (display.value !== "") {
                let num = parseFloat(display.value);
                display.value = num ** 2;
                input = display.value;
            }
        }
        else if (button.id === "cube") {
            if (display.value !== "") {
                let num = parseFloat(display.value);
                display.value = num ** 3;
                input = display.value;
            }
        }
        else if (button.id === "sqrt") {
            if (display.value !== "") {
                let num = parseFloat(display.value);
                display.value = Math.sqrt(num);
                input = display.value;
            }
        }
        else if (button.id === "percent") {
            if (display.value !== "") {
                let num = parseFloat(display.value);
                display.value = num / 100;
                input = display.value;
            }
        }
        else {
            input += button.getAttribute("data-value");
            display.value = input;
        }
    });
});
