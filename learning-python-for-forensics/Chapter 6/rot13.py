def rotCode(data):
      """
      The rotCode function encodes/decodes data using string indexing
      :param data: A string
      :return: The rot-13 encoded/decoded string
      """
      rot_chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
              'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
  
      substitutions = []
  
      # Walk through each individual character
      for c in data:
  
          # Walk through each individual character
          if c.isupper():
  
                  try:
                      # Find the position of the character in rot_chars list
                      index = rot_chars.index(c.lower())
                  except ValueError:
                      substitutions.append(c)
                      continue
  
                  # Calculate the relative index that is 13 characters away from the index
                  substitutions.append((rot_chars[(index-13)]).upper())
  
          else:
  
                  try:
                      # Find the position of the character in rot_chars list
                      index = rot_chars.index(c)
                  except ValueError:
                      substitutions.append(c)
                      continue
  
                  substitutions.append(rot_chars[((index-13))])
  
      return ''.join(substitutions)
    
if __name__ == '__main__':
     print rotCode('Jul, EBG-13?')
