function show_password() {
  var field = document.getElementById("passwordField");
  if (field.type === "password") {
    field.type = "text";
  } else {
    field.type = "password";
  }
}