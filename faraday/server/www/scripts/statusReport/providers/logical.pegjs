{
   function processName(name) {
      var processedName = "";
      switch (name) {
          case 'accountability':
          case 'availability':
          case 'confidentiality':
          case 'integrity':
              processedName = 'impact_' + name;
              break;
          case 'service':
              processedName = 'service__name';
              break;
          case 'easeofresolution':
          case 'ease_of_resolution':
              processedName = 'ease_of_resolution';
              break;
          case 'web':
          case 'type':
              processedName = 'type';
              break;
          case 'creator':
              processedName = 'creator_command_tool';
              break;
          case 'policy_violations':
          case 'policyviolations':
              processedName = 'policy_violations__name';
              break;
          case 'host_os':
              processedName = 'host__os';
              break;
          case 'refs':
          case 'ref':
              processedName = 'references__name';
              break;
          case 'evidence':
              processedName = 'evidence__filename';
              break;
          case 'params':
          case 'parameters':
              processedName = 'parameters';
              break;
          case 'pname':
          case 'parameter_name':
              processedName = 'parameter_name';
              break;
          case 'query':
          case 'query_string':
              processedName = 'query_string';
              break;
          case 'tags':
          case 'tag':
              processedName = 'tags__name';
              break;
          case 'port':
          case 'service_port':
              processedName = 'service__port';
              break;
          case 'protocol':
          case 'service_protocol':
              processedName = 'service__protocol';
              break;
          case 'hostname':
              processedName = 'hostnames';
              break;
          default:
              processedName = name;
              break;
      }
      return processedName;
   }


   function processOperator(name, operator) {
       var processedOperator = "";
       name = processName(name);
       switch (name) {
           case 'confirmed':
           case 'impact_accountability':
           case 'impact_availability':
           case 'impact_confidentiality':
           case 'impact_integrity':
           case 'ease_of_resolution':
           case 'type':
           case 'id':
               processedOperator = operator !== 'not' ? '==' : '!=';
               break;
           case 'severity':
           case 'target':
           case 'hostnames':
           case 'policy_violations__name':
           case 'references__name':
           case 'status':
           case 'status_code':
               processedOperator = operator !== 'not' ? 'eq' : '!=';
               break;
           case 'service__name':
           case 'service__port':
           case 'service__protocol':
           case 'host__os':
               processedOperator = operator !== 'not' ? 'has' : '!=';
               break;
           case 'evidence__filename':
           case 'tags__name':
               processedOperator = operator !== 'not' ? 'any' : '!=';
               break;
           default:
               processedOperator = operator !== 'not' ? 'ilike' : '!=';
               break;
       }

       return processedOperator;
   }


   function processValue(name, operator, value) {
        name = processName(name);
        operator = processOperator(name, operator);
        var val = value;

        if (val === 'info') val = 'informational';
        if (val === 'med') val = 'medium';

        if (operator === 'ilike' && name !== 'creator_command_tool') {
            val = '%' + value + '%';
        }
        return val;
   }

   function processLogicalNot(operand){
        try{
            operand.val = operand.val.replace(/%/g,'');
            return {
                  name: operand.name,
                  op: processOperator(operand.name, 'not') ,
                  val: processValue(operand.name, 'not', operand.val)
            }
        }catch(e){
            throw '"NOT" expression only can contain one operand'
            return null;
        }


   }

}



start
  = logical_or /
  free_exp /
  token:token { return {name:'name', op:'ilike', val: '%'+ token + '%'}}

free_exp
  = exp : token optional: (":" / "." / ws / "'" / "-" / "/" / token)*
  {
         return {
             name: 'name',
             op: 'ilike' ,
             val: processValue(name, null, exp += optional.join(""))
         }
    }

logical_or
  = left:logical_and ws+ "or" ws+ right:logical_or { return {"or": [left, right]} }
  / logical_and

logical_and
  = left:logical_not ws+ "and" ws+ right:logical_and { return {"and": [left, right]} }
  / logical_not

logical_not
  = "not" ws* operand:logical_not { return processLogicalNot(operand) }
  / primary

primary
  = term
  / "(" logical_or:logical_or ")" { return logical_or; }

term
  = expression
  / name:token ":" value:token
  {
      return {
          name: processName(name),
          op: processOperator(name, null) ,
          val: processValue(name, null, value)
      }
 }

expression
  = name: token ':' '"' mandatory: token optional: (":" / "." / ws / "'" / "-" / "/" / token)*  '"'
  {
       return {
           name: processName(name),
           op: processOperator(name, null) ,
           val: processValue(name, null, mandatory += optional.join(""))
       }
  }

token
  = token:[a-zA-Z0-9_.-/]+ { return token.join(""); }

ws
  = [ \t]
