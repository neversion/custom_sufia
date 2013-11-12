# -*- coding: utf-8 -*-
module MultimeidaHelper

  def render_edit_field_partial(key, locals)
    binding.pry
    render_edit_field_partial_with_action('generic_files', key, locals)
  end

  def render_field(key,locals)
    binding.pry
  end
  def render_field_single(key,locals)
    #binding.pry
    return render :partial => str, :locals=>locals.merge({key: key})
  end


end
