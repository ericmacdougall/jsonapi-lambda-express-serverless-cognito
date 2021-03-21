module.exports = length => {
  let code = '';

  for (let i = 0; i < length; i++) {
    code += Math.round(Math.random() * 9);
  }

  return code;
};
